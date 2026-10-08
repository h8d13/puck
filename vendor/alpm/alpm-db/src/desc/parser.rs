//! Parser for [alpm-db-desc] files.
//!
//! [alpm-db-desc]: https://alpm.archlinux.page/specifications/alpm-db-desc.5.html

use std::str::FromStr;

use alpm_parsers::{iter_str_context, prelude::*};
use alpm_types::{
    Architecture,
    BuildDate,
    ExtraData,
    ExtraDataEntry,
    FullVersion,
    Group,
    InstalledSize,
    License,
    Name,
    OptionalDependency,
    PackageBaseName,
    PackageDescription,
    PackageInstallReason,
    PackageRelation,
    PackageValidation,
    Packager,
    RelationOrSoname,
    Url,
};
use strum::{Display, EnumString, VariantNames};
use winnow::{
    ascii::{line_ending, space0, till_line_ending},
    combinator::{
        alt,
        cut_err,
        delimited,
        eof,
        not,
        opt,
        peek,
        preceded,
        repeat,
        repeat_till,
        terminated,
    },
    error::ErrMode,
    token::take_while,
};

use crate::libalpm;

/// A known section name in an [alpm-db-desc] file.
///
/// Section names are e.g. `%NAME%` or `%VERSION%`.
///
/// [alpm-db-desc]: https://alpm.archlinux.page/specifications/alpm-db-desc.5.html
#[derive(Clone, Debug, Display, EnumString, Eq, Hash, PartialEq, VariantNames)]
#[strum(serialize_all = "UPPERCASE")]
pub enum SectionKeyword {
    /// %NAME%
    Name,
    /// %VERSION%
    Version,
    /// %BASE%
    Base,
    /// %DESC%
    Desc,
    /// %URL%
    Url,
    /// %ARCH%
    Arch,
    /// %BUILDDATE%
    BuildDate,
    /// %INSTALLDATE%
    InstallDate,
    /// %PACKAGER%
    Packager,
    /// %SIZE%
    Size,
    /// %GROUPS%
    Groups,
    /// %REASON%
    Reason,
    /// %LICENSE%
    License,
    /// %VALIDATION%
    Validation,
    /// %REPLACES%
    Replaces,
    /// %DEPENDS%
    Depends,
    /// %OPTDEPENDS%
    OptDepends,
    /// %CONFLICTS%
    Conflicts,
    /// %PROVIDES%
    Provides,
    /// %XDATA%
    XData,
}

impl SectionKeyword {
    /// Recognizes a [`SectionKeyword`] in an input string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use alpm_db::desc::SectionKeyword;
    /// use alpm_parsers::prelude::*;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let (remaining, kw) = SectionKeyword::parser.parse_peek(Input::new("%NAME%\nfoo\n"))?;
    /// assert_eq!(kw, SectionKeyword::Name);
    /// assert_eq!(*remaining, "foo\n");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the input does not start with a valid
    /// `%SECTION%` header followed by a newline.
    pub fn parser<'a>(input: &mut Input<'a>) -> PResult<'a, Self> {
        let section = delimited("%", take_while(1.., |c| c != '%'), "%");
        terminated(
            preceded(space0, section.try_map(Self::from_str)),
            line_ending,
        )
        .parse_next(input)
    }
}

/// A single logical section from a database desc file.
#[derive(Clone, Debug)]
pub enum Section {
    /// %NAME%
    Name(Name),
    /// %VERSION%
    Version(FullVersion),
    /// %BASE%
    Base(PackageBaseName),
    /// %DESC%
    Desc(PackageDescription),
    /// %URL%
    Url(Option<Url>),
    /// %ARCH%
    Arch(Architecture),
    /// %BUILDDATE%
    BuildDate(BuildDate),
    /// %INSTALLDATE%
    InstallDate(BuildDate),
    /// %PACKAGER%
    Packager(Packager),
    /// %SIZE%
    Size(InstalledSize),
    /// %GROUPS%
    Groups(Vec<Group>),
    /// %REASON%
    Reason(PackageInstallReason),
    /// %LICENSE%
    License(Vec<License>),
    /// %VALIDATION%
    Validation(Vec<PackageValidation>),
    /// %REPLACES%
    Replaces(Vec<PackageRelation>),
    /// %DEPENDS%
    Depends(Vec<RelationOrSoname>),
    /// %OPTDEPENDS%
    OptDepends(Vec<OptionalDependency>),
    /// %CONFLICTS%
    Conflicts(Vec<PackageRelation>),
    /// %PROVIDES%
    Provides(Vec<RelationOrSoname>),
    /// %XDATA%
    XData(ExtraData),
    /// %MAKEDEPENDS%, only read by [`parse_libalpm`]
    MakeDepends(Vec<PackageRelation>),
    /// %CHECKDEPENDS%, only read by [`parse_libalpm`]
    CheckDepends(Vec<PackageRelation>),
}

/// One or multiple newlines.
///
/// This also handles the case where there might be multiple lines with spaces.
fn newlines<'a>(input: &mut Input<'a>) -> PResult<'a, ()> {
    repeat(0.., line_ending).parse_next(input)
}

/// Where a list of values ends.
#[derive(Clone, Copy, Debug)]
enum ListEnd {
    /// At a blank line, at the next section header or at the end of the file.
    Spec,
    /// At a blank line or at the end of the file, as libalpm reads lists: a line that looks like a
    /// section header is a value.
    Libalpm,
}

/// Recognizes the end of a list of values, without consuming anything.
///
/// A list of values ends at a blank line, at the next section header or at the end of the file.
fn end_of_values<'a>(input: &mut Input<'a>) -> PResult<'a, ()> {
    peek(alt((
        line_ending.map(|_| ()),
        SectionKeyword::parser.map(|_| ()),
        eof.map(|_| ()),
    )))
    .parse_next(input)
}

/// Recognizes the end of a list of values according to `end`, without consuming anything.
fn end_of_list<'a>(end: ListEnd, input: &mut Input<'a>) -> PResult<'a, ()> {
    match end {
        ListEnd::Spec => end_of_values(input),
        ListEnd::Libalpm => libalpm::end_of_block(input),
    }
}

/// A parser helper, which returns a [`FromStr`]-style parser for types that don't implement their
/// own parser.
///
/// Parses until the end of the current line. The line ending itself is not consumed.
/// Wraps the returned parser in a named layer.
///
/// # Errors
///
/// Returns an error if the next token cannot be parsed into `T`.
/// The error message of `T::from_str` is preserved as external error.
fn try_value_from<'a, T>(layer: &str) -> impl Parser<Input<'a>, T, ErrMode<ParseStack<'a>>>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    till_line_ending.try_map(T::from_str).layer(layer)
}

/// A parser helper for multi-value types, which returns a [`FromStr`]-style parser for types that
/// don't implement their own parser.
///
/// Parses a list of values, where each value is in its own line.
/// Repeats until the list ends according to `end`.
/// The line ending of the last value is not consumed.
///
/// # Errors
///
/// Returns an error if a value cannot be parsed into `T` or if the
/// section layout does not match expectations.
fn try_values_from<'a, T>(
    layer: &str,
    end: ListEnd,
) -> impl Parser<Input<'a>, Vec<T>, ErrMode<ParseStack<'a>>>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    move |input: &mut Input<'a>| -> PResult<'a, Vec<T>> {
        repeat_till(
            0..,
            // A value, followed by the line ending that separates it from the next value.
            terminated(
                try_value_from(layer),
                opt(terminated(
                    line_ending,
                    not(|i: &mut Input<'a>| end_of_list(end, i)),
                )),
            ),
            |i: &mut Input<'a>| end_of_list(end, i),
        )
        .map(|(outs, _)| outs)
        .parse_next(input)
    }
}

/// Parses a list of values, where each value is in its own line.
///
/// The Parser `P` is used to parse the value of each line.
///
/// Repeats until the list ends according to `end`.
/// The line ending of the last value is not consumed.
///
/// # Errors
///
/// Returns an error if a value cannot be parsed into `T` or if the
/// section layout does not match expectations.
fn values<'a, T, P>(
    type_parser: P,
    layer: &str,
    end: ListEnd,
) -> impl Parser<Input<'a>, Vec<T>, ErrMode<ParseStack<'a>>>
where
    P: Parser<Input<'a>, T, ErrMode<ParseStack<'a>>>,
{
    let mut type_parser = type_parser;
    let parser = move |input: &mut Input<'a>| -> PResult<'a, Vec<T>> {
        repeat_till(
            0..,
            // A value, followed by the line ending that separates it from the next value.
            terminated(
                type_parser.by_ref(),
                opt(terminated(
                    line_ending,
                    not(|i: &mut Input<'a>| end_of_list(end, i)),
                )),
            ),
            |i: &mut Input<'a>| end_of_list(end, i),
        )
        .map(|(outs, _)| outs)
        .parse_next(input)
    };

    parser.layer(layer)
}

/// Parses a single `%SECTION%` block and returns a [`Section`] variant.
///
/// # Errors
///
/// Returns an error if:
///
/// - the section name is invalid or not recognized,
/// - the section body contains malformed values,
/// - or the section does not terminate properly.
fn section<'a>(input: &mut Input<'a>) -> PResult<'a, Section> {
    // Parse and validate the header keyword first.
    let section_keyword = cut_err(SectionKeyword::parser)
        .description("expected a valid section name that is enclosed in `%` characters.")
        .context_with(iter_str_context!([SectionKeyword::VARIANTS]))
        .layer("section header")
        .parse_next(input)?;

    let section = section_value(input, section_keyword, ListEnd::Spec)?;

    // Consume the newline or handle end-of-file gracefully.
    alt((line_ending, eof)).parse_next(input)?;

    Ok(section)
}

/// Parses the value or values of a section with the given keyword.
///
/// Every value parser stops before the line ending of its last line, lists end according to
/// `end`.
///
/// # Errors
///
/// Returns an error if the section body contains malformed values.
fn section_value<'a>(
    input: &mut Input<'a>,
    section_keyword: SectionKeyword,
    end: ListEnd,
) -> PResult<'a, Section> {
    let section = match section_keyword {
        SectionKeyword::Name => Section::Name(Name::parser_until_line_ending(input)?),
        SectionKeyword::Version => Section::Version(FullVersion::parser_until_line_ending(input)?),
        SectionKeyword::Base => Section::Base(PackageBaseName::parser_until_line_ending(input)?),
        SectionKeyword::Desc => Section::Desc(
            till_line_ending
                .map(PackageDescription::new)
                .parse_next(input)?,
        ),
        SectionKeyword::Url => Section::Url(
            alt((
                // Handle the case of an empty URL
                till_line_ending
                    .verify(|s: &str| s.trim().is_empty())
                    .map(|_s: &str| None),
                // Handle the case of an existing URL
                till_line_ending
                    .try_map(Url::from_str)
                    .map(Some)
                    .layer("url field"),
            ))
            .parse_next(input)?,
        ),
        SectionKeyword::Arch => Section::Arch(Architecture::parser_until_line_ending(input)?),
        SectionKeyword::BuildDate => {
            Section::BuildDate(try_value_from("build date").parse_next(input)?)
        }
        SectionKeyword::InstallDate => {
            Section::InstallDate(try_value_from("install date").parse_next(input)?)
        }
        SectionKeyword::Packager => Section::Packager(Packager::parser_until_line_ending(input)?),
        SectionKeyword::Size => Section::Size(try_value_from("size").parse_next(input)?),
        SectionKeyword::Groups => Section::Groups(try_values_from("group", end).parse_next(input)?),
        SectionKeyword::Reason => {
            Section::Reason(try_value_from("install reason").parse_next(input)?)
        }
        SectionKeyword::License => {
            Section::License(try_values_from("license", end).parse_next(input)?)
        }
        SectionKeyword::Validation => Section::Validation(
            values(
                PackageValidation::parser_until_line_ending,
                "validation",
                end,
            )
            .parse_next(input)?,
        ),
        SectionKeyword::Replaces => Section::Replaces(
            values(PackageRelation::parser_until_line_ending, "replaces", end).parse_next(input)?,
        ),
        SectionKeyword::Depends => Section::Depends(
            values(RelationOrSoname::parser_until_line_ending, "depends", end).parse_next(input)?,
        ),
        SectionKeyword::OptDepends => Section::OptDepends(
            values(
                OptionalDependency::parser_until_line_ending,
                "optdepends",
                end,
            )
            .parse_next(input)?,
        ),
        SectionKeyword::Conflicts => Section::Conflicts(
            values(PackageRelation::parser_until_line_ending, "conflicts", end)
                .parse_next(input)?,
        ),
        SectionKeyword::Provides => Section::Provides(
            values(RelationOrSoname::parser_until_line_ending, "provides", end)
                .parse_next(input)?,
        ),
        SectionKeyword::XData => Section::XData(
            values(ExtraDataEntry::parser_until_line_ending, "xdata", end)
                .try_map(ExtraData::try_from)
                .parse_next(input)?,
        ),
    };

    Ok(section)
}

/// Parses all `%SECTION%` blocks from the given input into a list of [`Section`]s.
///
/// This is the top-level parser used by the higher-level file constructors.
///
/// # Errors
///
/// Returns an error if:
///
/// - any section header is missing or malformed,
/// - a section value list fails to parse,
/// - or the overall structure of the file is inconsistent.
pub(crate) fn sections<'a>(input: &mut Input<'a>) -> PResult<'a, Vec<Section>> {
    cut_err(repeat_till(
        0..,
        // Empty lines between sections are ignored.
        preceded(newlines, section.layer("alpm-repo-desc file value section")),
        terminated(opt(newlines), eof),
    ))
    .parse_next(input)
    .map(|(sections, _)| sections)
}

/// Parses the value or values of the section with the header `%name%` as libalpm reads them.
///
/// Returns [`None`] for a section libalpm does not know.
///
/// # Errors
///
/// Returns an error if the section body contains malformed values.
fn libalpm_section<'a>(input: &mut Input<'a>, name: &str) -> PResult<'a, Option<Section>> {
    let section = match name {
        // libalpm reads them from any desc file, though it never writes them to a local database
        "MAKEDEPENDS" => Section::MakeDepends(
            values(
                PackageRelation::parser_until_line_ending,
                "makedepends",
                ListEnd::Libalpm,
            )
            .parse_next(input)?,
        ),
        "CHECKDEPENDS" => Section::CheckDepends(
            values(
                PackageRelation::parser_until_line_ending,
                "checkdepends",
                ListEnd::Libalpm,
            )
            .parse_next(input)?,
        ),
        name => match SectionKeyword::from_str(name) {
            Ok(keyword) => section_value(input, keyword, ListEnd::Libalpm)?,
            Err(_) => return Ok(None),
        },
    };
    Ok(Some(section))
}

/// Parses all sections from the given input the way libalpm's `local_db_read` reads them.
///
/// - Section headers are whole lines compared as they are: an indented header, or one followed
///   by `\r\n`, is not a known header.
/// - A line that is not a known header starts an unknown section, which is skipped up to the next
///   blank line.
/// - Lists end at a blank line or at the end of the file only.
/// - Blank lines are ignored.
///
/// Sections are returned in file order. Repeated and missing sections are left to the caller.
///
/// # Errors
///
/// Returns an error if a value of a known section is malformed.
pub(crate) fn libalpm_sections<'a>(input: &mut Input<'a>) -> PResult<'a, Vec<Section>> {
    let mut sections = Vec::new();
    while !input.is_empty() {
        let line = libalpm::line.parse_next(input)?;
        let name = line
            .strip_prefix('%')
            .and_then(|line| line.strip_suffix('%'))
            .unwrap_or_default();
        let section = (|i: &mut Input<'a>| libalpm_section(i, name))
            .layer("alpm-db-desc file value section")
            .parse_next(input)?;
        match section {
            Some(section) => {
                sections.push(section);
                alt((line_ending, eof)).parse_next(input)?;
            }
            None if line.is_empty() => {}
            // libalpm warns about an unknown key and skips its values
            None => {
                while !input.is_empty() && !input.starts_with('\n') {
                    libalpm::line.parse_next(input)?;
                }
            }
        }
    }
    Ok(sections)
}

/// Parses [alpm-db-desc] data the way libalpm reads a local database desc file.
///
/// This is meant for reading what pacman reads, e.g. desc files that were written by older
/// versions of pacman or edited by hand. Section headers are whole lines, unknown sections are
/// skipped up to the next blank line, lists end at a blank line or at the end of the file only and
/// blank lines are ignored.
///
/// Unlike [`DbDescFileV1`][crate::desc::DbDescFileV1] and
/// [`DbDescFileV2`][crate::desc::DbDescFileV2], the sections are returned in file order without
/// checking which ones are present: libalpm leaves missing sections unset, overwrites a repeated
/// single-value section and appends a repeated list.
///
/// # Examples
///
/// ```
/// use alpm_db::desc::{Section, parse_libalpm};
///
/// # fn main() -> Result<(), alpm_db::Error> {
/// let sections = parse_libalpm("%FOO%\nbar\n\n%GROUPS%\nutils\n\n%GROUPS%\ncli\n")?;
/// assert_eq!(sections.len(), 2);
/// assert!(matches!(&sections[0], Section::Groups(groups) if groups.len() == 1));
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if a value of a known section is malformed.
///
/// [alpm-db-desc]: https://alpm.archlinux.page/specifications/alpm-db-desc.5.html
pub fn parse_libalpm(s: &str) -> Result<Vec<Section>, crate::Error> {
    Ok(libalpm_sections.parse(Input::new(s))?)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    /// Ensures that the libalpm reader returns the sections libalpm reads, in file order.
    #[rstest]
    #[case::empty("", "")]
    #[case::blank_lines("\n\n%BASE%\nfoo\n\n\n\n%BASE%\nbar\n", "Base Base")]
    #[case::unknown_section("%FOO%\nbar\nbaz\n\n%BASE%\nfoo\n", "Base")]
    #[case::unknown_section_at_end("%BASE%\nfoo\n\n%FOO%\nbar", "Base")]
    #[case::stray_line("%BASE%\nfoo\nbar\n%DESC%\nx\n\n%DESC%\ny\n", "Base Desc")]
    #[case::indented_header(" %BASE%\nfoo\n", "")]
    #[case::crlf("%BASE%\r\nfoo\r\n\r\n%DESC%\r\nx\r\n", "")]
    #[case::header_in_list("%GROUPS%\na\n%DESC%\n\n%BASE%\nfoo\n", "Groups(2) Base")]
    #[case::empty_list("%GROUPS%\n\n%BASE%\nfoo\n", "Groups(0) Base")]
    #[case::repeated("%GROUPS%\na\n\n%GROUPS%\nb\nc\n", "Groups(1) Groups(2)")]
    #[case::makedepends("%MAKEDEPENDS%\ngcc\nmake>=4\n", "MakeDepends(2)")]
    #[case::checkdepends("%CHECKDEPENDS%\npython\n", "CheckDepends(1)")]
    fn libalpm_sections_in_file_order(#[case] input: &str, #[case] expected: &str) -> TestResult {
        let names: Vec<String> = parse_libalpm(input)?
            .iter()
            .map(|section| match section {
                Section::Base(_) => "Base".to_string(),
                Section::Desc(_) => "Desc".to_string(),
                Section::Groups(groups) => format!("Groups({})", groups.len()),
                Section::MakeDepends(v) => format!("MakeDepends({})", v.len()),
                Section::CheckDepends(v) => format!("CheckDepends({})", v.len()),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names.join(" "), expected);
        Ok(())
    }

    /// Ensures that a malformed value of a known section is an error.
    #[test]
    fn libalpm_sections_fail_on_malformed_value() {
        assert!(parse_libalpm("%FOO%\nbar\n\n%BUILDDATE%\nnot a date\n").is_err());
    }
}
