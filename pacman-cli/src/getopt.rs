// glibc getopt_long (posix/getopt.c, 2.44), the parser pacman.c drives
//
// the C keeps its state in the globals optind, optarg, optopt, opterr
// and a static _getopt_data: here one `Getopt` value. optind = 0 forces
// a full reinit like in glibc. nextchar is a position in argv instead of
// a pointer into it, None once spent (the C points at the nul): argv is
// only permuted while it is spent. long options with a flag pointer,
// getopt_long_only and the POSIX "W;" extension are not used by pacman
// and not ported: every match returns its val. longopts is never NULL (pacman passes its
// table). messages are the untranslated msgids, written to `err` where
// glibc writes to stderr.
use std::ffi::c_char;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasArg {
	No,
	Required,
	Optional,
}

// struct option without the flag pointer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongOpt {
	pub name: &'static [u8],
	pub has_arg: HasArg,
	pub val: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ordering {
	RequireOrder,
	Permute,
	ReturnInOrder,
}

#[derive(Clone, Debug)]
pub struct Getopt {
	pub optind: usize,
	pub opterr: bool,
	pub optopt: i32,
	pub optarg: Option<Vec<u8>>,
	// getenv("POSIXLY_CORRECT") != NULL, read at initialization
	pub posixly_correct: bool,
	initialized: bool,
	// (argv index, byte offset) of the next short option character
	nextchar: Option<(usize, usize)>,
	ordering: Ordering,
	first_nonopt: usize,
	last_nonopt: usize,
}

// plain char in the C: the byte sign extends where char is signed
fn char_int(c: u8) -> i32 {
	i32::from(c as c_char)
}

impl Getopt {
	// the static initial state: optind 1, opterr 1, not initialized.
	// optopt is the internal getopt_data one, zeroed: glibc copies it
	// over the global (statically '?') after every call
	pub fn new(posixly_correct: bool) -> Self {
		Getopt {
			optind: 1,
			opterr: true,
			optopt: 0,
			optarg: None,
			posixly_correct,
			initialized: false,
			nextchar: None,
			ordering: Ordering::Permute,
			first_nonopt: 0,
			last_nonopt: 0,
		}
	}

	// _getopt_initialize: the optstring past its ordering prefix
	fn initialize<'a>(&mut self, optstring: &'a [u8]) -> &'a [u8] {
		if self.optind == 0 {
			self.optind = 1;
		}
		self.first_nonopt = self.optind;
		self.last_nonopt = self.optind;
		self.nextchar = None;
		let rest = match optstring.first() {
			Some(b'-') => {
				self.ordering = Ordering::ReturnInOrder;
				&optstring[1..]
			}
			Some(b'+') => {
				self.ordering = Ordering::RequireOrder;
				&optstring[1..]
			}
			_ => {
				self.ordering = if self.posixly_correct {
					Ordering::RequireOrder
				} else {
					Ordering::Permute
				};
				optstring
			}
		};
		self.initialized = true;
		rest
	}

	// exchange: the options in [last_nonopt, optind) move before the
	// non-options in [first_nonopt, last_nonopt), both keep their order
	fn exchange(&mut self, argv: &mut [Vec<u8>]) {
		let (bottom, middle, top) =
			(self.first_nonopt, self.last_nonopt, self.optind);
		argv[bottom..top].rotate_left(middle - bottom);
		self.first_nonopt += self.optind - self.last_nonopt;
		self.last_nonopt = self.optind;
	}

	// getopt_long: the option's val or character, '?' (':' with a
	// leading ':' in optstring) on errors, 1 for a non-option in
	// RETURN_IN_ORDER, -1 at the end with optind at the first non-option
	pub fn getopt_long(
		&mut self,
		argv: &mut [Vec<u8>],
		optstring: &[u8],
		longopts: &[LongOpt],
		longind: &mut usize,
		err: &mut Vec<u8>,
	) -> i32 {
		let argc = argv.len();
		let mut print_errors = self.opterr;
		if argc < 1 {
			return -1;
		}
		self.optarg = None;

		let optstring = if self.optind == 0 || !self.initialized {
			self.initialize(optstring)
		} else if matches!(optstring.first(), Some(b'-' | b'+')) {
			&optstring[1..]
		} else {
			optstring
		};
		if optstring.first() == Some(&b':') {
			print_errors = false;
		}

		if self.nextchar.is_none()
			&& let Some(r) = self.advance(
				argv,
				optstring,
				longopts,
				longind,
				print_errors,
				err,
			) {
			return r;
		}
		self.short_option(argv, optstring, print_errors, err)
	}

	// the "advance to the next ARGV-element" block. Some is a return
	// value, None leaves nextchar on a short option cluster
	fn advance(
		&mut self,
		argv: &mut [Vec<u8>],
		optstring: &[u8],
		longopts: &[LongOpt],
		longind: &mut usize,
		print_errors: bool,
		err: &mut Vec<u8>,
	) -> Option<i32> {
		let argc = argv.len();
		let nonoption =
			|a: &[u8]| a.first() != Some(&b'-') || a.len() == 1;

		// optind may have been moved back by the caller
		if self.last_nonopt > self.optind {
			self.last_nonopt = self.optind;
		}
		if self.first_nonopt > self.optind {
			self.first_nonopt = self.optind;
		}

		if self.ordering == Ordering::Permute {
			if self.first_nonopt != self.last_nonopt
				&& self.last_nonopt != self.optind
			{
				self.exchange(argv);
			} else if self.last_nonopt != self.optind {
				self.first_nonopt = self.optind;
			}
			while self.optind < argc
				&& nonoption(&argv[self.optind])
			{
				self.optind += 1;
			}
			self.last_nonopt = self.optind;
		}

		// "--" ends the options, swapped with earlier non-options as
		// if it were an option
		if self.optind != argc && argv[self.optind] == b"--" {
			self.optind += 1;
			if self.first_nonopt != self.last_nonopt
				&& self.last_nonopt != self.optind
			{
				self.exchange(argv);
			} else if self.first_nonopt == self.last_nonopt {
				self.first_nonopt = self.optind;
			}
			self.last_nonopt = argc;
			self.optind = argc;
		}

		if self.optind == argc {
			if self.first_nonopt != self.last_nonopt {
				self.optind = self.first_nonopt;
			}
			return Some(-1);
		}

		if nonoption(&argv[self.optind]) {
			if self.ordering == Ordering::RequireOrder {
				return Some(-1);
			}
			self.optarg = Some(argv[self.optind].clone());
			self.optind += 1;
			return Some(1);
		}

		if argv[self.optind][1] == b'-' {
			self.nextchar = Some((self.optind, 2));
			return Some(self.long_option(
				argv,
				optstring,
				longopts,
				longind,
				print_errors,
				err,
			));
		}
		self.nextchar = Some((self.optind, 1));
		None
	}

	// process_long_option, nextchar past the "--"
	fn long_option(
		&mut self,
		argv: &[Vec<u8>],
		optstring: &[u8],
		longopts: &[LongOpt],
		longind: &mut usize,
		print_errors: bool,
		err: &mut Vec<u8>,
	) -> i32 {
		let (i, off) = self.nextchar.unwrap();
		let text = &argv[i][off..];
		let namelen = text.iter().position(|&c| c == b'=');
		let name = &text[..namelen.unwrap_or(text.len())];
		let argv0 = &argv[0];

		let mut found = longopts.iter().position(|p| p.name == name);
		if found.is_none() {
			// abbreviations: matches differing in has_arg or val
			// are ambiguous, exact duplicates are not
			let mut ambig: Vec<usize> = Vec::new();
			for (n, p) in longopts.iter().enumerate() {
				if !p.name.starts_with(name) {
					continue;
				}
				match found {
					None => found = Some(n),
					Some(f) => {
						let q = &longopts[f];
						if q.has_arg != p.has_arg
							|| q.val != p.val
						{
							if ambig.is_empty() {
								ambig.push(f);
							}
							ambig.push(n);
						}
					}
				}
			}
			if !ambig.is_empty() {
				if print_errors {
					err.extend_from_slice(argv0);
					err.extend_from_slice(b": option '--");
					err.extend_from_slice(text);
					err.extend_from_slice(
						b"' is ambiguous; possibilities:",
					);
					for n in ambig {
						err.extend_from_slice(b" '--");
						err.extend_from_slice(
							longopts[n].name,
						);
						err.push(b'\'');
					}
					err.push(b'\n');
				}
				self.nextchar = None;
				self.optind += 1;
				self.optopt = 0;
				return char_int(b'?');
			}
		}

		let Some(n) = found else {
			if print_errors {
				err.extend_from_slice(argv0);
				err.extend_from_slice(
					b": unrecognized option '--",
				);
				err.extend_from_slice(text);
				err.extend_from_slice(b"'\n");
			}
			self.nextchar = None;
			self.optind += 1;
			self.optopt = 0;
			return char_int(b'?');
		};

		let p = &longopts[n];
		self.optind += 1;
		self.nextchar = None;
		if let Some(eq) = namelen {
			if p.has_arg == HasArg::No {
				if print_errors {
					err.extend_from_slice(argv0);
					err.extend_from_slice(b": option '--");
					err.extend_from_slice(p.name);
					err.extend_from_slice(
						b"' doesn't allow an argument\n",
					);
				}
				self.optopt = p.val;
				return char_int(b'?');
			}
			self.optarg = Some(text[eq + 1..].to_vec());
		} else if p.has_arg == HasArg::Required {
			if self.optind < argv.len() {
				self.optarg = Some(argv[self.optind].clone());
				self.optind += 1;
			} else {
				if print_errors {
					err.extend_from_slice(argv0);
					err.extend_from_slice(b": option '--");
					err.extend_from_slice(p.name);
					err.extend_from_slice(
						b"' requires an argument\n",
					);
				}
				self.optopt = p.val;
				return missing(optstring);
			}
		}
		*longind = n;
		p.val
	}

	// the next character of a short option cluster
	fn short_option(
		&mut self,
		argv: &[Vec<u8>],
		optstring: &[u8],
		print_errors: bool,
		err: &mut Vec<u8>,
	) -> i32 {
		let (i, off) = self.nextchar.unwrap();
		let arg = &argv[i];
		let c = arg[off];
		let rest = off + 1;
		// optind moves on when the last character is taken. a spent
		// nextchar is None: the index would go stale on permutation
		if rest == arg.len() {
			self.optind += 1;
			self.nextchar = None;
		} else {
			self.nextchar = Some((i, rest));
		}

		let temp = optstring.iter().position(|&o| o == c);
		let Some(t) = temp.filter(|_| c != b':' && c != b';') else {
			if print_errors {
				err.extend_from_slice(&argv[0]);
				err.extend_from_slice(b": invalid option -- '");
				err.push(c);
				err.extend_from_slice(b"'\n");
			}
			self.optopt = char_int(c);
			return char_int(b'?');
		};

		let colons = &optstring[t + 1..];
		if colons.first() != Some(&b':') {
			return char_int(c);
		}
		if colons.get(1) == Some(&b':') {
			// optional argument: only attached
			if rest < arg.len() {
				self.optarg = Some(arg[rest..].to_vec());
				self.optind += 1;
			}
			self.nextchar = None;
			return char_int(c);
		}
		let mut r = char_int(c);
		if rest < arg.len() {
			self.optarg = Some(arg[rest..].to_vec());
			self.optind += 1;
		} else if self.optind == argv.len() {
			if print_errors {
				err.extend_from_slice(&argv[0]);
				err.extend_from_slice(
					b": option requires an argument -- '",
				);
				err.push(c);
				err.extend_from_slice(b"'\n");
			}
			self.optopt = char_int(c);
			r = missing(optstring);
		} else {
			self.optarg = Some(argv[self.optind].clone());
			self.optind += 1;
		}
		self.nextchar = None;
		r
	}
}

// a missing required argument: ':' when optstring starts with ':'
fn missing(optstring: &[u8]) -> i32 {
	if optstring.first() == Some(&b':') {
		char_int(b':')
	} else {
		char_int(b'?')
	}
}
