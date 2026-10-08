//! Line handling of libalpm's local database reader.
//!
//! libalpm reads desc and files data line by line and only strips the `\n`: lines end at `\n`
//! and a blank line is a single `\n`.

use alpm_parsers::prelude::*;
use winnow::{
    combinator::{alt, eof, peek, terminated},
    token::take_till,
};

/// Recognizes one line: everything up to the next `\n`, which is consumed.
pub(crate) fn line<'a>(input: &mut Input<'a>) -> PResult<'a, &'a str> {
    terminated(take_till(0.., '\n'), alt(("\n", eof))).parse_next(input)
}

/// Recognizes the end of a block of lines, a blank line or the end of the file, without consuming
/// anything.
pub(crate) fn end_of_block<'a>(input: &mut Input<'a>) -> PResult<'a, ()> {
    peek(alt(("\n".void(), eof.void()))).parse_next(input)
}
