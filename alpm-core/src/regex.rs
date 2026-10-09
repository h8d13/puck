//! glibc regcomp(3)/regexec(3) as pacman calls them: REG_EXTENDED and
//! REG_NOSUB, with REG_ICASE and REG_NEWLINE as flags; only match or
//! no-match is ever used (lib/libalpm/db.c, remove.c, src/pacman/files.c).
//! remove.c leaves REG_NOSUB out, which only matters for anchors inside
//! {m,n} copies right before a group (see Compiler)
//!
//! semantics are glibc's in the C.UTF-8 locale. pacman calls
//! setlocale(LC_ALL, ""), other locales differ (collation rules, single
//! byte charsets) and are not modelled. character classes and towupper
//! take std's Unicode properties instead of glibc's tables (Class::has).
//!
//! translation:
//! - parsing follows posix/regcomp.c token by token so every pattern gets
//!   the same error; regcomp folds REG_ERPAREN into Paren
//! - C.UTF-8 has no collation rules (nrules 0): ranges take single-byte
//!   end points and compare code points, [. .] and [= =] take one byte
//! - like glibc the matcher works on bytes: literals are byte sequences,
//!   '.' and bracket expressions take whole characters. invalid UTF-8
//!   bytes are characters of their own that only literals match
//! - REG_ICASE upper-cases pattern and text (towupper), so escaped
//!   letters keep their case and match nothing, `[:lower:]`/`[:upper:]` in a
//!   bracket become `[:alpha:]`
//! - without REG_ICASE, bracket expressions, \w \s and word anchors, glibc
//!   matches in single-byte mode (optimize_utf8): matches may start inside
//!   a character and '.' only checks UTF-8 structure
//! - anchors are epsilon moves gated by context, like glibc's node
//!   constraints: the "next" half is checked against what the following
//!   step consumes, a single byte for literals and ASCII sets; a step over
//!   '\n' gives the newline context even without REG_NEWLINE
//! - matching: Pike VM over byte positions, O(len * insts). patterns with
//!   back-references use a depth-first search over (pc, position,
//!   captures), memoized so it stays polynomial, capped at MAX_STATES
//!   after which is_match gives up with false. the search takes any
//!   capture assignment that works, glibc misses some when the referenced
//!   group is repeated
//! - instruction count is capped at MAX_INSTS (glibc goes on until malloc
//!   fails), larger {m,n} expansions give Space
use std::collections::HashSet;
use std::ffi::c_int;

use crate::util::until_nul;

/// regcomp cflags besides REG_EXTENDED, which is implied
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
	pub icase: bool,
	pub newline: bool,
}

/// regcomp errors glibc returns for REG_EXTENDED patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	BadPattern,
	Collate,
	Ctype,
	Escape,
	Subreg,
	Bracket,
	Paren,
	Brace,
	BadBrace,
	Range,
	Space,
	Repeat,
	Size,
}

impl Error {
	/// reg_errcode_t value in regex.h
	pub fn code(self) -> c_int {
		match self {
			Error::BadPattern => 2,
			Error::Collate => 3,
			Error::Ctype => 4,
			Error::Escape => 5,
			Error::Subreg => 6,
			Error::Bracket => 7,
			Error::Paren => 8,
			Error::Brace => 9,
			Error::BadBrace => 10,
			Error::Range => 11,
			Error::Space => 12,
			Error::Repeat => 13,
			Error::Size => 15,
		}
	}
}

/// a compiled pattern, regex_t
#[derive(Debug, Clone)]
pub struct Regex {
	insts: Vec<Inst>,
	charsets: Vec<Charset>,
	icase: bool,
	newline: bool,
	/// glibc optimize_utf8 applied: matched as single bytes
	sb: bool,
	/// groups used by back-references, bit k for \k+1
	refs: u16,
	/// bytes a match can start with, None when it may start anywhere
	fastmap: Option<Box<[bool; 256]>>,
}

const WEOF: u32 = u32::MAX;
const RE_DUP_MAX: i32 = 0x7fff;
const BRACKET_NAME_BUF_SIZE: usize = 32;
const MAX_INSTS: usize = 1 << 20;
const MAX_STATES: usize = 1 << 20;
// unset position in back-reference search states
const UNSET: u32 = u32::MAX;
// search state flag: arrived by a single-byte step over '\n'
const STEPPED_NL: u32 = 0x100;

// node constraints, regex_internal.h
const PREV_WORD: u16 = 0x1;
const PREV_NOTWORD: u16 = 0x2;
const NEXT_WORD: u16 = 0x4;
const NEXT_NOTWORD: u16 = 0x8;
const PREV_NEWLINE: u16 = 0x10;
const NEXT_NEWLINE: u16 = 0x20;
const PREV_BEGBUF: u16 = 0x40;
const NEXT_ENDBUF: u16 = 0x80;
const NEXT_MASK: u16 = NEXT_WORD | NEXT_NOTWORD | NEXT_NEWLINE | NEXT_ENDBUF;
// \b and \B, expanded by the parser
const WORD_DELIM: u16 = 0x100;
const NOT_WORD_DELIM: u16 = 0x200;

const LINE_FIRST: u16 = PREV_NEWLINE;
const LINE_LAST: u16 = NEXT_NEWLINE;
const BUF_FIRST: u16 = PREV_BEGBUF;
const BUF_LAST: u16 = NEXT_ENDBUF;
const WORD_FIRST: u16 = PREV_NOTWORD | NEXT_WORD;
const WORD_LAST: u16 = PREV_WORD | NEXT_NOTWORD;
const INSIDE_WORD: u16 = PREV_WORD | NEXT_WORD;
const INSIDE_NOTWORD: u16 = PREV_NOTWORD | NEXT_NOTWORD;

// character contexts
const CTX_WORD: u8 = 1;
const CTX_NEWLINE: u8 = 2;
const CTX_BEGBUF: u8 = 4;
const CTX_ENDBUF: u8 = 8;

fn prev_ok(c: u16, ctx: u8) -> bool {
	let word = ctx & CTX_WORD != 0;
	!(c & PREV_WORD != 0 && !word
		|| c & PREV_NOTWORD != 0 && word
		|| c & PREV_NEWLINE != 0 && ctx & CTX_NEWLINE == 0
		|| c & PREV_BEGBUF != 0 && ctx & CTX_BEGBUF == 0)
}

fn next_ok(c: u16, ctx: u8) -> bool {
	let word = ctx & CTX_WORD != 0;
	!(c & NEXT_WORD != 0 && !word
		|| c & NEXT_NOTWORD != 0 && word
		|| c & NEXT_NEWLINE != 0 && ctx & CTX_NEWLINE == 0
		|| c & NEXT_ENDBUF != 0 && ctx & CTX_ENDBUF == 0)
}

// IS_WIDE_WORD_CHAR
fn is_word(wc: u32) -> bool {
	wc == u32::from(b'_') || Class::Alnum.has(wc)
}

enum Mb {
	Char(u32, usize),
	// a valid start cut short by the end of the input
	Short,
	Bad,
}

// glibc mbrtowc for UTF-8 on the pending state bytes followed by the
// input: forms up to 6 bytes, no overlongs, no surrogates
fn mbrtowc(s: &[u8]) -> Mb {
	let c = u32::from(s[0]);
	let (n, min, mut wc) = match c {
		0..=0x7f => return Mb::Char(c, 1),
		0xc2..=0xdf => (2, 0x80, c & 0x1f),
		0xe0..=0xef => (3, 0x800, c & 0x0f),
		0xf0..=0xf7 => (4, 0x10000, c & 0x07),
		0xf8..=0xfb => (5, 0x20_0000, c & 0x03),
		0xfc..=0xfd => (6, 0x400_0000, c & 0x01),
		_ => return Mb::Bad,
	};
	for i in 1..n {
		let Some(&b) = s.get(i) else {
			return Mb::Short;
		};
		if b & 0xc0 != 0x80 {
			return Mb::Bad;
		}
		wc = wc << 6 | u32::from(b & 0x3f);
	}
	if wc < min || (0xd800..=0xdfff).contains(&wc) {
		return Mb::Bad;
	}
	Mb::Char(wc, n)
}

// wcrtomb
fn encode(wc: u32, out: &mut Vec<u8>) {
	if wc < 0x80 {
		out.push(wc as u8);
		return;
	}
	let n = match wc {
		0x80..0x800 => 2,
		0x800..0x1_0000 => 3,
		0x1_0000..0x20_0000 => 4,
		0x20_0000..0x400_0000 => 5,
		_ => 6,
	};
	let lead = [0, 0, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc][n];
	out.push(lead | (wc >> (6 * (n - 1))) as u8);
	for k in (0..n - 1).rev() {
		out.push(0x80 | (wc >> (6 * k) & 0x3f) as u8);
	}
}

// re_string_t: the bytes matched (upper-cased under REG_ICASE), the wide
// char at each character head and WEOF inside characters, as
// build_wcs_buffer/build_wcs_upper_buffer produce them
struct Str {
	buf: Vec<u8>,
	wcs: Vec<u32>,
	// raw byte at each byte's source offset, pattern only: escapes and
	// class names read the original case
	orig: Vec<u8>,
	// some character changed length when upper-cased (offsets_needed)
	resized: bool,
}

impl Str {
	fn new(raw: &[u8], icase: bool, keep_orig: bool) -> Str {
		let mut s = Str {
			buf: Vec::with_capacity(raw.len()),
			wcs: Vec::with_capacity(raw.len()),
			orig: Vec::new(),
			resized: false,
		};
		let mut up = Vec::new();
		// mbstate_t: bytes of a started character
		let mut pending: Vec<u8> = Vec::new();
		let mut i = 0;
		while i < raw.len() {
			let b = raw[i];
			// ASCII in the initial state: mbrtowc gives the byte,
			// towupper its ASCII upper case
			if b.is_ascii() && pending.is_empty() {
				let up = if icase {
					b.to_ascii_uppercase()
				} else {
					b
				};
				s.buf.push(up);
				s.wcs.push(u32::from(up));
				if keep_orig {
					s.orig.push(b);
				}
				i += 1;
				continue;
			}
			// the state's bytes (under 6) and up to 6 more, on the stack
			let mut stack = [0u8; 12];
			let k = pending.len();
			let more = (raw.len() - i).min(6);
			stack[..k].copy_from_slice(&pending);
			stack[k..k + more].copy_from_slice(&raw[i..i + more]);
			let cat = &stack[..k + more];
			let (wc, used) = match mbrtowc(cat) {
				Mb::Char(wc, n) => {
					let used = n - pending.len();
					pending.clear();
					(wc, used)
				}
				m => {
					// a lone byte, wc is the byte. build_wcs_upper_buffer
					// keeps the state of a character cut by the end, the
					// next bytes then complete it
					if icase && matches!(m, Mb::Short) {
						pending = cat.to_vec();
					}
					s.buf.push(raw[i]);
					s.wcs.push(u32::from(raw[i]));
					if keep_orig {
						s.orig.push(raw[i]);
					}
					i += 1;
					continue;
				}
			};
			let wcu = if icase { towupper(wc) } else { wc };
			up.clear();
			if wcu == wc {
				up.extend_from_slice(&raw[i..i + used]);
			} else {
				encode(wcu, &mut up);
			}
			s.resized |= up.len() != used;
			for (k, &b) in up.iter().enumerate() {
				s.buf.push(b);
				s.wcs.push(if k == 0 { wcu } else { WEOF });
				if keep_orig {
					s.orig.push(raw[i + k.min(used - 1)]);
				}
			}
			i += used;
		}
		s
	}

	fn len(&self) -> usize {
		self.buf.len()
	}

	// re_string_first_byte
	fn head(&self, i: usize) -> bool {
		i == self.len() || self.wcs[i] != WEOF
	}

	// re_string_char_size_at: bytes up to the next head
	fn char_size(&self, i: usize) -> usize {
		let mut n = 1;
		while i + n < self.len() && self.wcs[i + n] == WEOF {
			n += 1;
		}
		n
	}

	// re_string_is_single_byte_char
	fn single_byte(&self, i: usize) -> bool {
		self.wcs[i] != WEOF
			&& (i + 1 == self.len() || self.wcs[i + 1] != WEOF)
	}
}

// ASCII part of a bracket: glibc masks the byte set to single-byte
// characters in UTF-8, the rest lives in the charset
#[derive(Debug, Clone, Copy, Default)]
struct Bits(u128);

impl Bits {
	fn set(&mut self, c: u32) {
		if c < 128 {
			self.0 |= 1 << c;
		}
	}

	fn has(self, c: u8) -> bool {
		c < 128 && self.0 >> c & 1 != 0
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
	Alnum,
	Alpha,
	Blank,
	Cntrl,
	Digit,
	Graph,
	Lower,
	Print,
	Punct,
	Space,
	Upper,
	Xdigit,
}

impl Class {
	fn from_name(name: &[u8]) -> Option<Class> {
		Some(match name {
			b"alnum" => Class::Alnum,
			b"alpha" => Class::Alpha,
			b"blank" => Class::Blank,
			b"cntrl" => Class::Cntrl,
			b"digit" => Class::Digit,
			b"graph" => Class::Graph,
			b"lower" => Class::Lower,
			b"print" => Class::Print,
			b"punct" => Class::Punct,
			b"space" => Class::Space,
			b"upper" => Class::Upper,
			b"xdigit" => Class::Xdigit,
			_ => return None,
		})
	}

	// iswctype in C.UTF-8 on std's Unicode properties, where glibc
	// 2.44 has its own i18n_ctype tables (code points that differ are
	// counted by the equivalence tests). digit and xdigit are ASCII only
	// in C.UTF-8, punct and print derive from graph like glibc's. wide
	// chars past U+10FFFF are in no class
	fn has(self, wc: u32) -> bool {
		let Some(c) = char::from_u32(wc) else {
			return false;
		};
		match self {
			Class::Alnum => c.is_alphabetic() || c.is_ascii_digit(),
			Class::Alpha => c.is_alphabetic(),
			Class::Blank => is_blank(c),
			Class::Cntrl => c.is_control(),
			Class::Digit => c.is_ascii_digit(),
			Class::Graph => is_graph(c),
			Class::Lower => c.is_lowercase(),
			Class::Print => is_graph(c) || c != '\t' && is_blank(c),
			Class::Punct => is_graph(c) && !Class::Alnum.has(wc),
			Class::Space => c.is_whitespace(),
			Class::Upper => c.is_uppercase(),
			Class::Xdigit => c.is_ascii_hexdigit(),
		}
	}
}

// POSIX blank: white space within a line, tab included. std has no line
// break property, the separators U+2028/2029 are the non-control ones
fn is_blank(c: char) -> bool {
	let line_sep = matches!(c, '\u{2028}' | '\u{2029}');
	c == '\t' || c.is_whitespace() && !c.is_control() && !line_sep
}

// anything visible: std has no general category, so unassigned code
// points count as graph (glibc: none of its classes)
fn is_graph(c: char) -> bool {
	!c.is_whitespace() && !c.is_control()
}

// towupper on char::to_uppercase where it gives one char. full mappings
// to several chars (U+00DF -> "SS", U+1FB3 -> "\u{391}\u{399}") keep the
// char, glibc takes the simple mapping there (U+1FB3 -> U+1FBC)
fn towupper(wc: u32) -> u32 {
	let Some(c) = char::from_u32(wc) else {
		return wc;
	};
	let mut up = c.to_uppercase();
	match (up.next(), up.next()) {
		(Some(u), None) => u32::from(u),
		_ => wc,
	}
}

// re_charset_t of a COMPLEX_BRACKET: multibyte characters only, the
// single-byte ones go through the Bits alternative
#[derive(Debug, Clone, Default)]
struct Charset {
	non_match: bool,
	mbchars: Vec<u32>,
	classes: Vec<Class>,
	ranges: Vec<(u32, u32)>,
}

impl Charset {
	fn is_complex(&self) -> bool {
		self.non_match
			|| !self.mbchars.is_empty()
			|| !self.classes.is_empty()
			|| !self.ranges.is_empty()
	}

	// check_node_accept_bytes: whole characters of two bytes or more, the
	// tail of a character when entered in its middle (wc is WEOF there)
	fn accept(&self, s: &Str, p: usize) -> usize {
		let n = s.char_size(p);
		if n <= 1 {
			return 0;
		}
		let wc = s.wcs[p];
		let hit = self.mbchars.contains(&wc)
			|| self.classes.iter().any(|c| c.has(wc))
			|| self.ranges.iter().any(|&(a, b)| a <= wc && wc <= b);
		if hit != self.non_match { n } else { 0 }
	}
}

// parse tree, glibc's bin_tree_t with NULL subtrees as Empty
#[derive(Debug)]
enum Node {
	Empty,
	Byte(u8, bool),
	Set(Bits),
	Complex(usize),
	Period,
	Anchor(u16),
	BackRef(u8),
	Group(usize, Box<Node>),
	Concat(Vec<Node>),
	Alt(Vec<Node>),
	Repeat(Box<Node>, u32, Option<u32>),
}

impl Node {
	fn concat(a: Node, b: Node) -> Node {
		match (a, b) {
			(Node::Empty, b) => b,
			(a, Node::Empty) => a,
			(Node::Concat(mut v), b) => {
				v.push(b);
				Node::Concat(v)
			}
			(a, b) => Node::Concat(vec![a, b]),
		}
	}

	fn alt(a: Node, b: Node) -> Node {
		match a {
			Node::Alt(mut v) => {
				v.push(b);
				Node::Alt(v)
			}
			a => Node::Alt(vec![a, b]),
		}
	}

	// optimize_utf8 preconditions: no COMPLEX_BRACKET, no word anchor
	fn single_byte_ok(&self) -> bool {
		match self {
			Node::Complex(_) => false,
			Node::Anchor(t) => matches!(
				*t,
				LINE_FIRST | LINE_LAST | BUF_FIRST | BUF_LAST
			),
			Node::Group(_, n) | Node::Repeat(n, _, _) => {
				n.single_byte_ok()
			}
			Node::Concat(v) | Node::Alt(v) => {
				v.iter().all(Node::single_byte_ok)
			}
			_ => true,
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
	Char,
	End,
	BackSlash,
	Alt,
	Star,
	Plus,
	Question,
	OpenDup,
	CloseDup,
	OpenSub,
	CloseSub,
	OpenBracket,
	Period,
	Anchor(u16),
	BackRef(u8),
	Word,
	NotWord,
	Space,
	NotSpace,
}

#[derive(Debug, Clone, Copy)]
struct Token {
	kind: Kind,
	c: u8,
	word: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BKind {
	Char,
	End,
	Range,
	Close,
	NonMatch,
	OpenColl,
	OpenEquiv,
	OpenClass,
}

#[derive(Debug, Clone, Copy)]
struct BToken {
	kind: BKind,
	c: u8,
	len: usize,
}

// bracket_elem_t
enum Elem {
	Sb(u8),
	Mb(u32),
	Coll(Vec<u8>),
	Equiv(Vec<u8>),
	Class(Vec<u8>),
}

struct Parser {
	s: Str,
	i: usize,
	tok: Token,
	icase: bool,
	newline: bool,
	nsub: usize,
	// completed_bkref_map, used_bkref_map
	completed: u16,
	used: u16,
	charsets: Vec<Charset>,
}

impl Parser {
	// re_string_peek_byte_case: an escaped byte keeps its original case
	// under REG_ICASE, unless upper-casing turned a non-ASCII character
	// into ASCII (dotless i, long s)
	fn case_byte(&self, i: usize) -> u8 {
		let s = &self.s;
		if !self.icase || !s.single_byte(i) {
			return s.buf[i];
		}
		let ch = s.orig[i];
		if s.resized && !ch.is_ascii() {
			s.buf[i]
		} else {
			ch
		}
	}

	// re_string_fetch_byte_case, for class names
	fn name_byte(&self, i: usize) -> u8 {
		let s = &self.s;
		if !self.icase {
			return s.buf[i];
		}
		if !s.resized {
			return s.orig[i];
		}
		if !s.head(i) || !s.orig[i].is_ascii() {
			return s.buf[i];
		}
		s.orig[i]
	}

	// peek_token for RE_SYNTAX_POSIX_EXTENDED, GNU escapes included
	fn peek(&self) -> (Token, usize) {
		let s = &self.s;
		let i = self.i;
		let mut t = Token {
			kind: Kind::End,
			c: 0,
			word: false,
		};
		if i >= s.len() {
			return (t, 0);
		}
		t.c = s.buf[i];
		t.kind = Kind::Char;
		if !s.head(i) {
			return (t, 1);
		}
		if t.c == b'\\' {
			if i + 1 >= s.len() {
				t.kind = Kind::BackSlash;
				return (t, 1);
			}
			t.c = self.case_byte(i + 1);
			t.word = is_word(s.wcs[i + 1]);
			t.kind = match t.c {
				b'1'..=b'9' => Kind::BackRef(t.c - b'1'),
				b'<' => Kind::Anchor(WORD_FIRST),
				b'>' => Kind::Anchor(WORD_LAST),
				b'b' => Kind::Anchor(WORD_DELIM),
				b'B' => Kind::Anchor(NOT_WORD_DELIM),
				b'w' => Kind::Word,
				b'W' => Kind::NotWord,
				b's' => Kind::Space,
				b'S' => Kind::NotSpace,
				b'`' => Kind::Anchor(BUF_FIRST),
				b'\'' => Kind::Anchor(BUF_LAST),
				_ => Kind::Char,
			};
			return (t, 2);
		}
		t.word = is_word(s.wcs[i]);
		t.kind = match t.c {
			b'|' => Kind::Alt,
			b'*' => Kind::Star,
			b'+' => Kind::Plus,
			b'?' => Kind::Question,
			b'{' => Kind::OpenDup,
			b'}' => Kind::CloseDup,
			b'(' => Kind::OpenSub,
			b')' => Kind::CloseSub,
			b'[' => Kind::OpenBracket,
			b'.' => Kind::Period,
			b'^' => Kind::Anchor(LINE_FIRST),
			b'$' => Kind::Anchor(LINE_LAST),
			_ => Kind::Char,
		};
		(t, 1)
	}

	fn fetch(&mut self) {
		let (t, n) = self.peek();
		self.tok = t;
		self.i += n;
	}

	// a branch stops at '|', the end, or ')' inside a group
	fn branch_end(&self, nest: usize) -> bool {
		matches!(self.tok.kind, Kind::Alt | Kind::End)
			|| nest > 0 && self.tok.kind == Kind::CloseSub
	}

	// parse_reg_exp
	fn reg_exp(&mut self, nest: usize) -> Result<Node, Error> {
		let initial = self.completed;
		let mut tree = self.branch(nest)?;
		while self.tok.kind == Kind::Alt {
			self.fetch();
			let branch = if self.branch_end(nest) {
				Node::Empty
			} else {
				// groups of other alternatives are not referable
				let accumulated = self.completed;
				self.completed = initial;
				let b = self.branch(nest)?;
				self.completed |= accumulated;
				b
			};
			tree = Node::alt(tree, branch);
		}
		Ok(tree)
	}

	// parse_branch
	fn branch(&mut self, nest: usize) -> Result<Node, Error> {
		let mut tree = self.expression(nest)?;
		while !self.branch_end(nest) {
			let e = self.expression(nest)?;
			tree = Node::concat(tree, e);
		}
		Ok(tree)
	}

	// parse_expression
	fn expression(&mut self, nest: usize) -> Result<Node, Error> {
		let tok = self.tok;
		let tree = match tok.kind {
			Kind::Char | Kind::CloseSub | Kind::CloseDup => {
				// ')' outside groups and '}' are literals
				// (RE_UNMATCHED_RIGHT_PAREN_ORD); the rest of a
				// multibyte character follows as partial bytes
				let mut t = Node::Byte(tok.c, tok.word);
				while self.i < self.s.len()
					&& !self.s.head(self.i)
				{
					self.fetch();
					t = Node::concat(
						t,
						Node::Byte(self.tok.c, false),
					);
				}
				t
			}
			Kind::OpenSub => self.sub_exp(nest + 1)?,
			Kind::OpenBracket => self.bracket_exp()?,
			Kind::BackRef(k) => {
				if self.completed & 1 << k == 0 {
					return Err(Error::Subreg);
				}
				self.used |= 1 << k;
				Node::BackRef(k)
			}
			// RE_CONTEXT_INVALID_OPS: nothing to repeat
			Kind::OpenDup
			| Kind::Star
			| Kind::Plus
			| Kind::Question => {
				return Err(Error::Repeat);
			}
			Kind::Anchor(t) => {
				let tree = match t {
					WORD_DELIM => Node::Alt(vec![
						Node::Anchor(WORD_FIRST),
						Node::Anchor(WORD_LAST),
					]),
					NOT_WORD_DELIM => Node::Alt(vec![
						Node::Anchor(INSIDE_WORD),
						Node::Anchor(INSIDE_NOTWORD),
					]),
					t => Node::Anchor(t),
				};
				// anchors take no repetition, "^*" fails on '*'
				self.fetch();
				return Ok(tree);
			}
			Kind::Period => Node::Period,
			Kind::Word => self.class_op(Class::Alnum, b"_", false),
			Kind::NotWord => {
				self.class_op(Class::Alnum, b"_", true)
			}
			Kind::Space => self.class_op(Class::Space, b"", false),
			Kind::NotSpace => {
				self.class_op(Class::Space, b"", true)
			}
			Kind::Alt | Kind::End => return Ok(Node::Empty),
			Kind::BackSlash => return Err(Error::Escape),
		};
		self.fetch();
		let mut tree = tree;
		while matches!(
			self.tok.kind,
			Kind::Star
				| Kind::Plus | Kind::Question
				| Kind::OpenDup
		) {
			tree = self.dup_op(tree)?;
		}
		Ok(tree)
	}

	// parse_sub_exp, the token after '(' is not fetched yet
	fn sub_exp(&mut self, nest: usize) -> Result<Node, Error> {
		let idx = self.nsub;
		self.nsub += 1;
		self.fetch();
		let tree = if self.tok.kind == Kind::CloseSub {
			Node::Empty
		} else {
			let t = self.reg_exp(nest)?;
			if self.tok.kind != Kind::CloseSub {
				return Err(Error::Paren);
			}
			t
		};
		if idx < 9 {
			self.completed |= 1 << idx;
		}
		Ok(Node::Group(idx, Box::new(tree)))
	}

	// fetch_number: -1 nothing read, -2 invalid
	fn number(&mut self) -> i32 {
		let mut num = -1;
		loop {
			self.fetch();
			let t = self.tok;
			if t.kind == Kind::End {
				return -2;
			}
			// an escaped "\," counts as the separator too
			if t.kind == Kind::CloseDup || t.c == b',' {
				return num;
			}
			num = if t.kind != Kind::Char
				|| !t.c.is_ascii_digit() || num == -2
			{
				-2
			} else if num == -1 {
				i32::from(t.c - b'0')
			} else {
				(RE_DUP_MAX + 1)
					.min(num * 10 + i32::from(t.c - b'0'))
			};
		}
	}

	// parse_dup_op
	fn dup_op(&mut self, elem: Node) -> Result<Node, Error> {
		let (start, end) = if self.tok.kind == Kind::OpenDup {
			let mut start = self.number();
			if start == -1 {
				if self.tok.kind == Kind::Char
					&& self.tok.c == b','
				{
					start = 0;
				} else {
					return Err(Error::BadBrace);
				}
			}
			let mut end = 0;
			if start != -2 {
				end = if self.tok.kind == Kind::CloseDup {
					start
				} else if self.tok.kind == Kind::Char
					&& self.tok.c == b','
				{
					self.number()
				} else {
					-2
				};
			}
			if start == -2 || end == -2 {
				// no RE_INVALID_INTERVAL_ORD
				return Err(if self.tok.kind == Kind::End {
					Error::Brace
				} else {
					Error::BadBrace
				});
			}
			if end != -1 && start > end
				|| self.tok.kind != Kind::CloseDup
			{
				return Err(Error::BadBrace);
			}
			if RE_DUP_MAX < if end == -1 { start } else { end } {
				return Err(Error::Size);
			}
			(start as u32, (end >= 0).then_some(end as u32))
		} else {
			let start = u32::from(self.tok.kind == Kind::Plus);
			let end =
				(self.tok.kind == Kind::Question).then_some(1);
			(start, end)
		};
		self.fetch();
		if matches!(elem, Node::Empty) || end == Some(0) {
			return Ok(Node::Empty);
		}
		Ok(Node::Repeat(Box::new(elem), start, end))
	}

	// peek_token_bracket, backslash is literal (no
	// RE_BACKSLASH_ESCAPE_IN_LISTS)
	fn peek_bracket(&self) -> BToken {
		let s = &self.s;
		let i = self.i;
		if i >= s.len() {
			return BToken {
				kind: BKind::End,
				c: 0,
				len: 0,
			};
		}
		let c = s.buf[i];
		let mut t = BToken {
			kind: BKind::Char,
			c,
			len: 1,
		};
		if !s.head(i) {
			return t;
		}
		if c == b'[' {
			let c2 = s.buf.get(i + 1).copied().unwrap_or(0);
			let kind = match c2 {
				b'.' => BKind::OpenColl,
				b'=' => BKind::OpenEquiv,
				b':' => BKind::OpenClass,
				_ => return t,
			};
			return BToken {
				kind,
				c: c2,
				len: 2,
			};
		}
		t.kind = match c {
			b'-' => BKind::Range,
			b']' => BKind::Close,
			b'^' => BKind::NonMatch,
			_ => BKind::Char,
		};
		t
	}

	// parse_bracket_element
	fn bracket_elem(
		&mut self,
		t: BToken,
		accept_hyphen: bool,
	) -> Result<Elem, Error> {
		let n = self.s.char_size(self.i);
		if n > 1 {
			let wc = self.s.wcs[self.i];
			self.i += n;
			return Ok(Elem::Mb(wc));
		}
		self.i += t.len;
		match t.kind {
			BKind::OpenColl
			| BKind::OpenEquiv
			| BKind::OpenClass => {
				return self.bracket_symbol(t);
			}
			// '-' is only literal first or last
			BKind::Range
				if !accept_hyphen
					&& self.peek_bracket().kind
						!= BKind::Close =>
			{
				return Err(Error::Range);
			}
			_ => {}
		}
		Ok(Elem::Sb(t.c))
	}

	// parse_bracket_symbol: [.x.] [=x=] [:x:]
	fn bracket_symbol(&mut self, t: BToken) -> Result<Elem, Error> {
		let len = self.s.len();
		if self.i >= len {
			return Err(Error::Bracket);
		}
		let mut name = Vec::new();
		loop {
			if name.len() >= BRACKET_NAME_BUF_SIZE {
				return Err(Error::Bracket);
			}
			let ch = if t.kind == BKind::OpenClass {
				self.name_byte(self.i)
			} else {
				self.s.buf[self.i]
			};
			self.i += 1;
			if self.i >= len {
				return Err(Error::Bracket);
			}
			if ch == t.c && self.s.buf[self.i] == b']' {
				break;
			}
			name.push(ch);
		}
		self.i += 1;
		Ok(match t.kind {
			BKind::OpenColl => Elem::Coll(name),
			BKind::OpenEquiv => Elem::Equiv(name),
			_ => Elem::Class(name),
		})
	}

	// parse_bracket_exp, '[' already consumed
	fn bracket_exp(&mut self) -> Result<Node, Error> {
		let mut sb = Bits::default();
		let mut cs = Charset::default();
		let mut t = self.peek_bracket();
		if t.kind == BKind::End {
			return Err(Error::BadPattern);
		}
		if t.kind == BKind::NonMatch {
			cs.non_match = true;
			if self.newline {
				// RE_HAT_LISTS_NOT_NEWLINE
				sb.set(u32::from(b'\n'));
			}
			self.i += t.len;
			t = self.peek_bracket();
			if t.kind == BKind::End {
				return Err(Error::BadPattern);
			}
		}
		// a leading ']' is literal
		if t.kind == BKind::Close {
			t.kind = BKind::Char;
		}
		let mut first = true;
		loop {
			let start = self.bracket_elem(t, first)?;
			first = false;
			t = self.peek_bracket();
			let mut range = None;
			if !matches!(start, Elem::Class(_) | Elem::Equiv(_)) {
				if t.kind == BKind::End {
					return Err(Error::Bracket);
				}
				if t.kind == BKind::Range {
					self.i += t.len;
					let t2 = self.peek_bracket();
					if t2.kind == BKind::End {
						return Err(Error::Bracket);
					}
					if t2.kind == BKind::Close {
						// trailing '-' is literal
						self.i -= t.len;
						t.kind = BKind::Char;
					} else {
						range = Some(t2);
					}
				}
			}
			if let Some(t2) = range {
				let end = self.bracket_elem(t2, true)?;
				t = self.peek_bracket();
				build_range(&mut sb, &mut cs, &start, &end)?;
			} else {
				match start {
					Elem::Sb(c) => sb.set(u32::from(c)),
					Elem::Mb(wc) => cs.mbchars.push(wc),
					// no collation rules: one byte names only
					Elem::Coll(name)
					| Elem::Equiv(name) => {
						if name.len() != 1 {
							return Err(
								Error::Collate,
							);
						}
						sb.set(u32::from(name[0]));
					}
					Elem::Class(name) => self
						.build_charclass(
							&mut sb, &mut cs, &name,
						)?,
				}
			}
			if t.kind == BKind::End {
				return Err(Error::Bracket);
			}
			if t.kind == BKind::Close {
				break;
			}
		}
		self.i += t.len;
		if cs.non_match {
			sb.0 = !sb.0;
		}
		Ok(self.bracket_node(sb, cs, false))
	}

	// SIMPLE_BRACKET, COMPLEX_BRACKET or both under an ALT
	fn bracket_node(
		&mut self,
		sb: Bits,
		cs: Charset,
		always: bool,
	) -> Node {
		if !always && !cs.is_complex() {
			return Node::Set(sb);
		}
		self.charsets.push(cs);
		let cx = Node::Complex(self.charsets.len() - 1);
		if always || sb.0 != 0 {
			Node::Alt(vec![Node::Set(sb), cx])
		} else {
			cx
		}
	}

	// build_charclass in a bracket
	fn build_charclass(
		&self,
		sb: &mut Bits,
		cs: &mut Charset,
		name: &[u8],
	) -> Result<(), Error> {
		let mut name = name;
		// the text is upper-cased, so either case class matches letters
		if self.icase && (name == b"upper" || name == b"lower") {
			name = b"alpha";
		}
		let class = Class::from_name(name).ok_or(Error::Ctype)?;
		cs.classes.push(class);
		for c in 0..128 {
			if class.has(c) {
				sb.set(c);
			}
		}
		Ok(())
	}

	// build_charclass_op: \w \W \s \S, always a SIMPLE/COMPLEX pair. the
	// negated forms take '\n' even under REG_NEWLINE
	fn class_op(
		&mut self,
		class: Class,
		extra: &[u8],
		non_match: bool,
	) -> Node {
		let mut sb = Bits::default();
		for c in 0..128 {
			if class.has(c) {
				sb.set(c);
			}
		}
		for &c in extra {
			sb.set(u32::from(c));
		}
		if non_match {
			sb.0 = !sb.0;
		}
		let cs = Charset {
			non_match,
			classes: vec![class],
			..Default::default()
		};
		self.bracket_node(sb, cs, true)
	}
}

// build_range_exp without collation rules: collseqmb is the identity on
// bytes, multibyte end points have no sequence value
fn build_range(
	sb: &mut Bits,
	cs: &mut Charset,
	start: &Elem,
	end: &Elem,
) -> Result<(), Error> {
	let seq = |e: &Elem| match e {
		Elem::Sb(c) => Ok(Some(u32::from(*c))),
		Elem::Coll(n) if n.len() == 1 => Ok(Some(u32::from(n[0]))),
		Elem::Equiv(_) | Elem::Class(_) => Err(Error::Range),
		_ => Ok(None),
	};
	let (a, b) = (seq(start)?, seq(end)?);
	let (Some(a), Some(b)) = (a, b) else {
		return Err(Error::Collate);
	};
	if a > b {
		return Err(Error::Range);
	}
	cs.ranges.push((a, b));
	for c in a..=b.min(127) {
		sb.set(c);
	}
	Ok(())
}

#[derive(Debug, Clone, Copy)]
enum Inst {
	// literal byte, IS_WIDE_WORD_CHAR of the character it starts
	Byte(u8, bool),
	Set(Bits),
	Complex(u32),
	Period,
	BackRef(u8),
	Anchor(u16),
	Split(u32, u32),
	Jmp(u32),
	Open(u8),
	Close(u8),
	// epsilon: unused group bounds, anchors without effect
	Nop,
	Match,
}

// glibc expands {m,n} by copying the tree (duplicate_tree) and marks the
// copies "duplicated". an anchor whose next node is such a copy keeps its
// constraint to itself (calc_eclosure_iter skips it), so it matches
// anywhere: in "(^a){2}" only the first '^' counts. dups records the flag
// per instruction, finish() turns those anchors into Nop
struct Compiler {
	insts: Vec<Inst>,
	dups: Vec<bool>,
	refs: u16,
}

impl Compiler {
	fn emit(&mut self, i: Inst, dup: bool) -> Result<u32, Error> {
		if self.insts.len() >= MAX_INSTS {
			return Err(Error::Space);
		}
		self.insts.push(i);
		self.dups.push(dup);
		Ok(self.insts.len() as u32 - 1)
	}

	fn here(&self) -> u32 {
		self.insts.len() as u32
	}

	// REG_NOSUB drops groups no reference uses, empty ones stay as
	// OPEN/CLOSE pairs (lower_subexp)
	fn keeps_group(&self, k: usize, e: &Node) -> bool {
		matches!(e, Node::Empty) || k < 9 && self.refs & 1 << k != 0
	}

	// the duplicated flag of the first node glibc builds for n
	fn first_dup(&self, n: &Node, dup: bool) -> bool {
		match n {
			Node::Group(k, e) if self.keeps_group(*k, e) => false,
			Node::Group(_, e) => self.first_dup(e, dup),
			Node::Concat(v) => self.first_dup(&v[0], dup),
			Node::Repeat(e, min, _) if *min > 0 => {
				self.first_dup(e, dup)
			}
			_ => dup,
		}
	}

	fn node(&mut self, n: &Node, dup: bool) -> Result<(), Error> {
		match n {
			Node::Empty => {}
			Node::Byte(c, w) => {
				_ = self.emit(Inst::Byte(*c, *w), dup)?
			}
			Node::Set(b) => _ = self.emit(Inst::Set(*b), dup)?,
			Node::Complex(i) => {
				_ = self.emit(Inst::Complex(*i as u32), dup)?
			}
			Node::Period => _ = self.emit(Inst::Period, dup)?,
			Node::Anchor(t) => {
				_ = self.emit(Inst::Anchor(*t), dup)?
			}
			Node::BackRef(k) => {
				_ = self.emit(Inst::BackRef(*k), dup)?
			}
			// only referenced groups need their positions
			Node::Group(k, e) if self.keeps_group(*k, e) => {
				let refd = *k < 9 && self.refs & 1 << k != 0;
				let (open, close) = if refd {
					(
						Inst::Open(*k as u8),
						Inst::Close(*k as u8),
					)
				} else {
					(Inst::Nop, Inst::Nop)
				};
				self.emit(open, false)?;
				self.node(e, dup)?;
				self.emit(close, false)?;
			}
			Node::Group(_, e) => self.node(e, dup)?,
			Node::Concat(v) => {
				for e in v {
					self.node(e, dup)?;
				}
			}
			Node::Alt(v) => {
				let mut jumps = Vec::new();
				for (i, e) in v.iter().enumerate() {
					if i + 1 == v.len() {
						self.node(e, dup)?;
						break;
					}
					let split = self
						.emit(Inst::Split(0, 0), dup)?;
					self.node(e, dup)?;
					jumps.push(
						self.emit(Inst::Jmp(0), dup)?
					);
					self.insts[split as usize] =
						Inst::Split(
							split + 1,
							self.here(),
						);
				}
				let end = self.here();
				for j in jumps {
					self.insts[j as usize] = Inst::Jmp(end);
				}
			}
			Node::Repeat(e, min, max) => {
				self.repeat(e, *min, *max, dup)?
			}
		}
		Ok(())
	}

	// parse_dup_op's shape: the first instance is the parsed tree, the
	// others copies
	fn repeat(
		&mut self,
		e: &Node,
		min: u32,
		max: Option<u32>,
		dup: bool,
	) -> Result<(), Error> {
		for i in 0..min {
			self.node(e, dup || i > 0)?;
		}
		let copy = dup || min > 0;
		let Some(max) = max else {
			let split = self.emit(Inst::Split(0, 0), dup)?;
			self.node(e, copy)?;
			self.emit(Inst::Jmp(split), dup)?;
			self.insts[split as usize] =
				Inst::Split(split + 1, self.here());
			return Ok(());
		};
		let mut splits = Vec::new();
		for i in min..max {
			// the ALT glibc builds first, then the next copy's own node
			let copy = copy || i > min;
			let flag = if i == min {
				dup
			} else {
				self.first_dup(e, true)
			};
			splits.push(self.emit(Inst::Split(0, 0), flag)?);
			self.node(e, copy)?;
		}
		let end = self.here();
		for s in splits {
			self.insts[s as usize] = Inst::Split(s + 1, end);
		}
		Ok(())
	}

	// anchors followed by a duplicated node lose their constraint
	fn finish(&mut self) {
		for pc in 0..self.insts.len() {
			if !matches!(self.insts[pc], Inst::Anchor(_)) {
				continue;
			}
			let mut next = pc + 1;
			while let Inst::Jmp(a) = self.insts[next] {
				next = a as usize;
			}
			if self.dups[next] {
				self.insts[pc] = Inst::Nop;
			}
		}
	}
}

impl Regex {
	/// regcomp(&reg, pattern, REG_EXTENDED | flags), pattern as a C string
	pub fn new(pattern: &[u8], flags: Flags) -> Result<Regex, Error> {
		let s = Str::new(until_nul(pattern), flags.icase, true);
		let mut p = Parser {
			s,
			i: 0,
			tok: Token {
				kind: Kind::End,
				c: 0,
				word: false,
			},
			icase: flags.icase,
			newline: flags.newline,
			nsub: 0,
			completed: 0,
			used: 0,
			charsets: Vec::new(),
		};
		p.fetch();
		// at nest 0 ')' is literal, so only the end stops this
		let tree = p.reg_exp(0)?;
		let mut c = Compiler {
			insts: Vec::new(),
			dups: Vec::new(),
			refs: p.used,
		};
		c.node(&tree, false)?;
		c.emit(Inst::Match, false)?;
		c.finish();
		let mut re = Regex {
			insts: c.insts,
			charsets: p.charsets,
			icase: flags.icase,
			newline: flags.newline,
			sb: !flags.icase && tree.single_byte_ok(),
			refs: p.used,
			fastmap: None,
		};
		re.fastmap = re.build_fastmap();
		Ok(re)
	}

	/// regexec(&reg, text, 0, NULL, 0) == 0, text as a C string
	pub fn is_match(&self, text: &[u8]) -> bool {
		let s = Str::new(until_nul(text), self.icase, false);
		let m = Matcher { re: self, s: &s };
		if self.refs == 0 { m.pike() } else { m.search() }
	}

	// re_compile_fastmap over the four initial states, which regexec
	// consults for every pattern. a back-reference to a group that can
	// be empty at the start is passed, any other stops the scan. None: a
	// match can start anywhere
	fn build_fastmap(&self) -> Option<Box<[bool; 256]>> {
		// groups whose close is reachable without consuming, glibc's
		// init_nodes fixpoint
		let mut pass = 0u16;
		loop {
			let mut closes = 0u16;
			for pc in self.first_insts(None, pass) {
				if let Inst::Close(k) = self.insts[pc] {
					closes |= 1 << k;
				}
			}
			if closes & !pass == 0 {
				break;
			}
			pass |= closes;
		}
		let mut map = Box::new([false; 256]);
		let ctxs = [0, CTX_WORD, CTX_NEWLINE, CTX_NEWLINE | CTX_BEGBUF];
		for ctx in ctxs {
			for pc in self.first_insts(Some(ctx), pass) {
				match self.insts[pc] {
					Inst::Byte(c, _) => {
						map[usize::from(c)] = true
					}
					Inst::Set(b) => {
						for c in 0..128 {
							map[usize::from(c)] |=
								b.has(c);
						}
					}
					Inst::Complex(i) => self
						.fastmap_complex(
							i as usize, &mut map,
						),
					Inst::Period | Inst::Match => {
						return None;
					}
					_ => {}
				}
			}
		}
		Some(map)
	}

	// lead bytes a COMPLEX_BRACKET can start with. glibc also adds the
	// towlower form of each character under REG_ICASE, which the
	// upper-cased text never starts with
	fn fastmap_complex(&self, i: usize, map: &mut [bool; 256]) {
		let cs = &self.charsets[i];
		if cs.non_match
			|| !cs.classes.is_empty()
			|| !cs.ranges.is_empty()
		{
			// every byte mbrtowc reports as an incomplete character
			map[0xc2..=0xfd].fill(true);
			return;
		}
		let mut buf = Vec::new();
		for &wc in &cs.mbchars {
			buf.clear();
			encode(wc, &mut buf);
			map[usize::from(buf[0])] = true;
		}
	}

	// instructions reachable from the start without consuming: PREV
	// constraints checked against ctx when given, back-references passed
	// for groups in pass
	fn first_insts(&self, ctx: Option<u8>, pass: u16) -> Vec<usize> {
		let mut seen = vec![false; self.insts.len()];
		let mut out = Vec::new();
		let mut stack = vec![0usize];
		while let Some(pc) = stack.pop() {
			if std::mem::replace(&mut seen[pc], true) {
				continue;
			}
			out.push(pc);
			match self.insts[pc] {
				Inst::Split(a, b) => {
					stack.extend([b as usize, a as usize])
				}
				Inst::Jmp(a) => stack.push(a as usize),
				Inst::Anchor(t) => {
					if ctx.is_none_or(|ctx| prev_ok(t, ctx))
					{
						stack.push(pc + 1);
					}
				}
				Inst::Open(_) | Inst::Close(_) | Inst::Nop => {
					stack.push(pc + 1)
				}
				Inst::BackRef(k) if pass & 1 << k != 0 => {
					stack.push(pc + 1)
				}
				_ => {}
			}
		}
		out
	}
}

struct Matcher<'a> {
	re: &'a Regex,
	s: &'a Str,
}

// stamp per (pc, next-constraint) pair, a new stamp clears the set
struct Seen {
	marks: Vec<u32>,
	stamp: u32,
}

impl Seen {
	fn new(n: usize) -> Seen {
		Seen {
			marks: vec![0; n * 16],
			stamp: 0,
		}
	}

	fn clear(&mut self) {
		self.stamp += 1;
	}

	fn insert(&mut self, pc: usize, cons: u16) -> bool {
		// the four NEXT bits, 0x4 0x8 0x20 0x80, packed in 0..16
		let c = usize::from(
			cons >> 2 & 3 | cons >> 3 & 4 | cons >> 4 & 8,
		);
		let m = &mut self.marks[pc * 16 + c];
		*m != self.stamp && {
			*m = self.stamp;
			true
		}
	}
}

impl Matcher<'_> {
	// re_string_context_at for the character at i
	fn ctx_char(&self, i: usize) -> u8 {
		let s = self.s;
		let wc = if self.re.sb {
			u32::from(s.buf[i])
		} else {
			let mut j = i;
			while s.wcs[j] == WEOF {
				j -= 1;
			}
			s.wcs[j]
		};
		// single-byte mode has no word anchors to ask
		if !self.re.sb && is_word(wc) {
			CTX_WORD
		} else if wc == u32::from(b'\n') && self.re.newline {
			CTX_NEWLINE
		} else {
			0
		}
	}

	// context before position p
	fn ctx_before(&self, p: usize) -> u8 {
		if p == 0 {
			CTX_NEWLINE | CTX_BEGBUF
		} else {
			self.ctx_char(p - 1)
		}
	}

	// context of the character at p
	fn ctx_after(&self, p: usize) -> u8 {
		if p == self.s.len() {
			CTX_NEWLINE | CTX_ENDBUF
		} else {
			self.ctx_char(p)
		}
	}

	// a byte consumed with build_trtable: '\n' always gives the newline
	// context, REG_NEWLINE or not
	fn ctx_stepped(&self, p: usize) -> u8 {
		if p > 0 && self.s.buf[p - 1] == b'\n' {
			CTX_NEWLINE
		} else {
			self.ctx_before(p)
		}
	}

	// re_search_internal tries every byte in single-byte mode, character
	// heads otherwise
	fn can_start(&self, p: usize) -> bool {
		self.re.sb || self.s.head(p)
	}

	// group_nodes_into_DFAstates: the NEXT constraint of a single-byte
	// step looks at the byte, and at the literal's own character
	fn byte_next_ok(&self, cons: u16, word: Option<bool>, b: u8) -> bool {
		if cons & NEXT_NEWLINE != 0 && b != b'\n'
			|| cons & NEXT_ENDBUF != 0
		{
			return false;
		}
		let ascii_word = b.is_ascii_alphanumeric() || b == b'_';
		if cons & NEXT_WORD != 0
			&& (word == Some(false) || b.is_ascii() && !ascii_word)
		{
			return false;
		}
		!(cons & NEXT_NOTWORD != 0
			&& (word == Some(true) || ascii_word))
	}

	// single-byte transition of a consuming instruction
	fn step_byte(&self, inst: Inst, cons: u16, p: usize) -> bool {
		let Some(&b) = self.s.buf.get(p) else {
			return false;
		};
		let (ok, word) = match inst {
			Inst::Byte(c, w) => (b == c, Some(w)),
			Inst::Set(bits) => (bits.has(b), None),
			// sb_char: ASCII only, the rest goes by character
			Inst::Period => (
				b.is_ascii()
					&& !(b == b'\n' && self.re.newline),
				None,
			),
			_ => (false, None),
		};
		ok && (cons == 0 || self.byte_next_ok(cons, word, b))
	}

	// transit_state_mb: bytes a multibyte step takes at p, 0 for none
	fn step_mb(&self, inst: Inst, cons: u16, p: usize) -> usize {
		if p >= self.s.len()
			|| !matches!(inst, Inst::Period | Inst::Complex(_))
			|| cons != 0 && !next_ok(cons, self.ctx_after(p))
		{
			return 0;
		}
		match inst {
			Inst::Period if self.re.sb => {
				utf8_period(&self.s.buf, p)
			}
			Inst::Period => {
				let n = self.s.char_size(p);
				if n > 1 { n } else { 0 }
			}
			Inst::Complex(i) => {
				self.re.charsets[i as usize].accept(self.s, p)
			}
			_ => 0,
		}
	}

	// epsilon closure of pc at the current position, consuming
	// instructions and Match land in run with their NEXT constraints.
	// stack is scratch space, empty between calls
	fn closure(
		&self,
		pc: u32,
		ctx: u8,
		seen: &mut Seen,
		run: &mut Vec<(u32, u16)>,
		stack: &mut Vec<(u32, u16)>,
	) {
		stack.push((pc, 0u16));
		while let Some((pc, cons)) = stack.pop() {
			if !seen.insert(pc as usize, cons) {
				continue;
			}
			match self.re.insts[pc as usize] {
				Inst::Split(a, b) => {
					stack.extend([(b, cons), (a, cons)])
				}
				Inst::Jmp(a) => stack.push((a, cons)),
				Inst::Anchor(t) => {
					if prev_ok(t, ctx) {
						stack.push((
							pc + 1,
							cons | t & NEXT_MASK,
						));
					}
				}
				Inst::Open(_) | Inst::Close(_) | Inst::Nop => {
					stack.push((pc + 1, cons))
				}
				_ => run.push((pc, cons)),
			}
		}
	}

	// Pike VM, threads for every start position run side by side. mb
	// steps land up to 6 bytes ahead, hence the ring of pending threads
	fn pike(&self) -> bool {
		let n = self.s.len();
		let insts = &self.re.insts;
		let mut ring: [Vec<u32>; 8] = Default::default();
		let mut seen = Seen::new(insts.len());
		let mut queued = Seen::new(insts.len());
		let mut run = Vec::new();
		let mut stack = Vec::new();
		// threads waiting in the ring
		let mut live = 0;
		let mut p = 0;
		while p <= n {
			// re_search_internal's fastmap skip: with no thread left
			// only a start can match, at a byte it may start with
			if let (0, Some(map)) = (live, &self.re.fastmap) {
				let rest = &self.s.buf[p..];
				match rest
					.iter()
					.position(|&b| map[usize::from(b)])
				{
					Some(i) => p += i,
					None => return false,
				}
			}
			let mut arrived = std::mem::take(&mut ring[p % 8]);
			live -= arrived.len();
			run.clear();
			let before = self.ctx_before(p);
			let stepped = self.ctx_stepped(p);
			seen.clear();
			for &pc in &arrived {
				let (s, r) = (&mut seen, &mut run);
				self.closure(pc, stepped, s, r, &mut stack);
			}
			if self.can_start(p) {
				if stepped != before {
					seen.clear();
				}
				let (s, r) = (&mut seen, &mut run);
				self.closure(0, before, s, r, &mut stack);
			}
			queued.clear();
			let after = self.ctx_after(p);
			for &(pc, cons) in &run {
				if !queued.insert(pc as usize, cons) {
					continue;
				}
				let inst = insts[pc as usize];
				if let Inst::Match = inst {
					if next_ok(cons, after) {
						return true;
					}
					continue;
				}
				if self.step_byte(inst, cons, p) {
					ring[(p + 1) % 8].push(pc + 1);
					live += 1;
				}
				let k = self.step_mb(inst, cons, p);
				if k > 0 {
					ring[(p + k) % 8].push(pc + 1);
					live += 1;
				}
			}
			arrived.clear();
			ring[p % 8] = arrived;
			p += 1;
		}
		false
	}

	// back-reference patterns: depth-first search over states, each
	// visited once. a state is [pc, pos, flags, quirk, then open, start,
	// end per referenced group]: flags hold the pending NEXT constraint
	// and STEPPED_NL, quirk the last position where an anchor relied on
	// the stepped newline
	fn search(&self) -> bool {
		let n = self.s.len();
		let groups: Vec<u8> =
			(0..9).filter(|k| self.re.refs & 1 << k != 0).collect();
		let mut seen: HashSet<Vec<u32>> = HashSet::new();
		let mut stack: Vec<Vec<u32>> = Vec::new();
		for p in 0..=n {
			if !self.can_start(p) {
				continue;
			}
			if let Some(map) = &self.re.fastmap {
				let b = self.s.buf.get(p).copied().unwrap_or(0);
				if !map[usize::from(b)] {
					continue;
				}
			}
			let mut st = vec![0, p as u32, 0];
			st.resize(4 + 3 * groups.len(), UNSET);
			stack.push(st);
			while let Some(st) = stack.pop() {
				if seen.contains(&st) {
					continue;
				}
				if seen.len() >= MAX_STATES {
					return false;
				}
				if self.expand(&st, &groups, &mut stack) {
					return true;
				}
				seen.insert(st);
			}
		}
		false
	}

	// pushes the successors of st, true when st is an accepting Match
	fn expand(
		&self,
		st: &[u32],
		groups: &[u8],
		stack: &mut Vec<Vec<u32>>,
	) -> bool {
		let (pc, p) = (st[0], st[1] as usize);
		let cons = st[2] as u16 & NEXT_MASK;
		let slot = |k: u8| {
			4 + 3 * groups.iter().position(|&g| g == k).unwrap()
		};
		let next = |pc: u32, p: usize, flags: u32| {
			let mut v = st.to_vec();
			(v[0], v[1], v[2]) = (pc, p as u32, flags);
			v
		};
		let inst = self.re.insts[pc as usize];
		match inst {
			Inst::Split(a, b) => {
				stack.push(next(b, p, st[2]));
				stack.push(next(a, p, st[2]));
			}
			Inst::Jmp(a) => stack.push(next(a, p, st[2])),
			Inst::Anchor(t) => {
				let flags = st[2] | u32::from(t & NEXT_MASK);
				if prev_ok(t, self.ctx_before(p)) {
					stack.push(next(pc + 1, p, flags));
				} else if st[2] & STEPPED_NL != 0
					&& prev_ok(t, CTX_NEWLINE)
				{
					let mut v = next(pc + 1, p, flags);
					v[3] = p as u32;
					stack.push(v);
				}
			}
			Inst::Nop => stack.push(next(pc + 1, p, st[2])),
			Inst::Open(k) => {
				let mut v = next(pc + 1, p, st[2]);
				v[slot(k)] = p as u32;
				stack.push(v);
			}
			Inst::Close(k) => {
				let i = slot(k);
				let mut v = next(pc + 1, p, st[2]);
				(v[i], v[i + 1], v[i + 2]) =
					(UNSET, st[i], p as u32);
				stack.push(v);
			}
			Inst::Match => return next_ok(cons, self.ctx_after(p)),
			Inst::BackRef(k) => {
				let i = slot(k);
				let (a, b) = (st[i + 1], st[i + 2]);
				// glibc re-derives the group's states by context
				// (check_arrival), losing a stepped newline used since
				// the group started
				if a == UNSET
					|| st[3] != UNSET && a <= st[3] || cons != 0
					&& !next_ok(cons, self.ctx_after(p))
				{
					return false;
				}
				let (a, b) = (a as usize, b as usize);
				let len = b - a;
				let buf = &self.s.buf;
				if p + len > buf.len()
					|| buf[a..b] != buf[p..p + len]
				{
					return false;
				}
				// an empty reference passes its constraint on
				let flags = if len == 0 {
					u32::from(cons)
				} else {
					0
				};
				stack.push(next(pc + 1, p + len, flags));
			}
			_ => {
				// prune_impossible_nodes re-checks single-byte steps
				// by context (check_node_accept)
				if self.step_byte(inst, cons, p)
					&& (cons == 0
						|| next_ok(
							cons,
							self.ctx_after(p),
						)) {
					let nl = self.s.buf[p] == b'\n';
					let flags =
						if nl { STEPPED_NL } else { 0 };
					stack.push(next(pc + 1, p + 1, flags));
				}
				let k = self.step_mb(inst, cons, p);
				if k > 0 {
					stack.push(next(pc + 1, p + k, 0));
				}
			}
		}
		false
	}
}

// OP_UTF8_PERIOD multibyte step: UTF-8 shape only, so surrogates and 5
// and 6 byte forms pass
fn utf8_period(b: &[u8], p: usize) -> usize {
	let c = b[p];
	if c < 0xc2 || p + 2 > b.len() {
		return 0;
	}
	let d = b[p + 1];
	// lead byte, then the smallest second byte that is no overlong
	let (n, low) = match c {
		0xc2..=0xdf => (2, 0x80),
		0xe0 => (3, 0xa0),
		0xe1..=0xef => (3, 0x80),
		0xf0 => (4, 0x90),
		0xf1..=0xf7 => (4, 0x80),
		0xf8 => (5, 0x88),
		0xf9..=0xfb => (5, 0x80),
		0xfc => (6, 0x84),
		0xfd => (6, 0x80),
		_ => return 0,
	};
	if d < low {
		return 0;
	}
	if p + n > b.len()
		|| !b[p + 1..p + n].iter().all(|&d| (0x80..=0xbf).contains(&d))
	{
		return 0;
	}
	n
}
