//! Parser for [alpm-repo-desc] files.
//!
//! [alpm-repo-desc]: https://alpm.archlinux.page/specifications/alpm-repo-desc.5.html

use std::str::FromStr;

use alpm_parsers::{iter_str_context, prelude::*};
use alpm_types::{
    Architecture,
    Base64OpenPGPSignature,
    BuildDate,
    CompressedSize,
    ExtraDataEntry,
    FullVersion,
    Group,
    InstalledSize,
    License,
    Md5Checksum,
    Name,
    OptionalDependency,
    PackageBaseName,
    PackageDescription,
    PackageFileName,
    PackageRelation,
    Packager,
    RelationOrSoname,
    Sha256Checksum,
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

/// A known section name in an [alpm-repo-desc] file.
///
/// Section names are e.g. `%NAME%` or `%VERSION%`.
///
/// [alpm-repo-desc]: https://alpm.archlinux.page/specifications/alpm-repo-desc.5.html
#[derive(Clone, Debug, Display, EnumString, Eq, Hash, PartialEq, VariantNames)]
#[strum(serialize_all = "UPPERCASE")]
pub enum SectionKeyword {
    /// %FILENAME%
    Filename,
    /// %Name%
    Name,
    /// %BASE%
    Base,
    /// %VERSION%
    Version,
    /// %DESC%
    Desc,
    /// %GROUPS%
    Groups,
    /// %CSIZE%
    CSize,
    /// %ISIZE%
    ISize,
    /// %MD5SUM%
    Md5Sum,
    /// %SHA256SUM%
    Sha256Sum,
    /// %PGPSIG%
    PgpSig,
    /// %URL%
    Url,
    /// %LICENSE%
    License,
    /// %ARCH%
    Arch,
    /// %BUILDDATE%
    BuildDate,
    /// %PACKAGER%
    Packager,
    /// %REPLACES%
    Replaces,
    /// %CONFLICTS%
    Conflicts,
    /// %PROVIDES%
    Provides,
    /// %DEPENDS%
    Depends,
    /// %OPTDEPENDS%
    OptDepends,
    /// %MAKEDEPENDS%
    MakeDepends,
    /// %CHECKDEPENDS%
    CheckDepends,
}

impl SectionKeyword {
    /// Recognizes a [`SectionKeyword`] in an input string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use alpm_parsers::prelude::*;
    /// use alpm_repo_db::desc::SectionKeyword;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let (remaining, kw) = SectionKeyword::parser
    ///     .parse_peek(Input::new("%NAME%\nfoo\n"))
    ///     .unwrap();
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

/// A single logical section from a repo desc file.
#[derive(Clone, Debug)]
pub enum Section {
    /// %FILENAME%
    Filename(PackageFileName),
    /// %NAME%
    Name(Name),
    /// %BASE%
    Base(PackageBaseName),
    /// %VERSION%
    Version(FullVersion),
    /// %DESC%
    Desc(PackageDescription),
    /// %GROUPS%
    Groups(Vec<Group>),
    /// %CSIZE%
    CSize(CompressedSize),
    /// %ISIZE%
    ISize(InstalledSize),
    /// %MD5SUM%
    Md5Sum(Md5Checksum),
    /// %SHA256SUM%
    Sha256Sum(Sha256Checksum),
    /// %PGPSIG%
    PgpSig(Base64OpenPGPSignature),
    /// %URL%
    Url(Option<Url>),
    /// %LICENSE%
    License(Vec<License>),
    /// %ARCH%
    Arch(Architecture),
    /// %BUILDDATE%
    BuildDate(BuildDate),
    /// %PACKAGER%
    Packager(Packager),
    /// %REPLACES%
    Replaces(Vec<PackageRelation>),
    /// %CONFLICTS%
    Conflicts(Vec<PackageRelation>),
    /// %PROVIDES%
    Provides(Vec<RelationOrSoname>),
    /// %DEPENDS%
    Depends(Vec<RelationOrSoname>),
    /// %OPTDEPENDS%
    OptDepends(Vec<OptionalDependency>),
    /// %MAKEDEPENDS%
    MakeDepends(Vec<PackageRelation>),
    /// %CHECKDEPENDS%
    CheckDepends(Vec<PackageRelation>),
    /// %DATA%, the extra data libalpm reads, only read by [`parse_libalpm`]
    Data(Vec<ExtraDataEntry>),
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

/// Recognizes the end of a list of values according to `end`, without consuming anything.
fn end_of_list<'a>(end: ListEnd, input: &mut Input<'a>) -> PResult<'a, ()> {
    match end {
        ListEnd::Spec => end_of_values(input),
        ListEnd::Libalpm => libalpm::end_of_block(input),
    }
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
        .description("expected a valid section name that is enclosed in `%` characters:")
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
        SectionKeyword::Filename => {
            Section::Filename(try_value_from("file name").parse_next(input)?)
        }
        SectionKeyword::Name => Section::Name(Name::parser_until_line_ending(input)?),
        SectionKeyword::Base => Section::Base(PackageBaseName::parser_until_line_ending(input)?),
        SectionKeyword::Version => Section::Version(FullVersion::parser_until_line_ending(input)?),
        SectionKeyword::Desc => Section::Desc(
            till_line_ending
                .map(PackageDescription::new)
                .parse_next(input)?,
        ),
        SectionKeyword::Groups => Section::Groups(try_values_from("group", end).parse_next(input)?),
        SectionKeyword::CSize => {
            Section::CSize(try_value_from("compressed size").parse_next(input)?)
        }
        SectionKeyword::ISize => {
            Section::ISize(try_value_from("installed size").parse_next(input)?)
        }
        SectionKeyword::Md5Sum => Section::Md5Sum(Md5Checksum::parser_until_line_ending(input)?),
        SectionKeyword::Sha256Sum => {
            Section::Sha256Sum(Sha256Checksum::parser_until_line_ending(input)?)
        }
        SectionKeyword::PgpSig => {
            Section::PgpSig(try_value_from("pgp signature").parse_next(input)?)
        }
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
        SectionKeyword::License => {
            Section::License(try_values_from("license", end).parse_next(input)?)
        }
        SectionKeyword::Arch => Section::Arch(Architecture::parser_until_line_ending(input)?),
        SectionKeyword::BuildDate => {
            Section::BuildDate(try_value_from("build date").parse_next(input)?)
        }
        SectionKeyword::Packager => Section::Packager(Packager::parser_until_line_ending(input)?),
        SectionKeyword::Replaces => Section::Replaces(
            values(PackageRelation::parser_until_line_ending, "replaces", end).parse_next(input)?,
        ),
        SectionKeyword::Conflicts => Section::Conflicts(
            values(PackageRelation::parser_until_line_ending, "conflicts", end)
                .parse_next(input)?,
        ),
        SectionKeyword::Provides => Section::Provides(
            values(RelationOrSoname::parser_until_line_ending, "provides", end)
                .parse_next(input)?,
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
        SectionKeyword::MakeDepends => Section::MakeDepends(
            values(
                PackageRelation::parser_until_line_ending,
                "makedepends",
                end,
            )
            .parse_next(input)?,
        ),
        SectionKeyword::CheckDepends => Section::CheckDepends(
            values(
                PackageRelation::parser_until_line_ending,
                "checkdepends",
                end,
            )
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
        preceded(newlines, section.layer("alpm-db-desc file value section")),
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
        // libalpm reads extra data from sync databases, repo-add does not write it yet
        "DATA" => Section::Data(
            values(
                ExtraDataEntry::parser_until_line_ending,
                "data",
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

/// Parses all sections from the given input the way libalpm's `sync_db_read` reads them.
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
            .layer("alpm-repo-desc file value section")
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

/// Parses [alpm-repo-desc] data the way libalpm reads a desc entry of a sync database.
///
/// This is meant for reading what pacman reads, e.g. repository databases created by other tools
/// or older versions of **repo-add**. Section headers are whole lines, unknown sections are skipped
/// up to the next blank line, lists end at a blank line or at the end of the file only and blank
/// lines are ignored.
///
/// Unlike [`RepoDescFileV1`][crate::desc::RepoDescFileV1] and
/// [`RepoDescFileV2`][crate::desc::RepoDescFileV2], the sections are returned in file order
/// without checking which ones are present or empty: libalpm leaves missing sections unset,
/// overwrites a repeated single-value section and appends a repeated list.
///
/// # Examples
///
/// ```
/// use alpm_repo_db::desc::{Section, parse_libalpm};
///
/// # fn main() -> Result<(), alpm_repo_db::Error> {
/// let sections = parse_libalpm("%FOO%\nbar\n\n%GROUPS%\n\n%GROUPS%\ncli\n")?;
/// assert_eq!(sections.len(), 2);
/// assert!(matches!(&sections[0], Section::Groups(groups) if groups.is_empty()));
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if a value of a known section is malformed.
///
/// [alpm-repo-desc]: https://alpm.archlinux.page/specifications/alpm-repo-desc.5.html
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
    #[case::data("%DATA%\npkgtype=pkg\nfoo=bar\n", "Data(2)")]
    #[case::data_without_pkgtype("%DATA%\nfoo=bar\n", "Data(1)")]
    fn libalpm_sections_in_file_order(#[case] input: &str, #[case] expected: &str) -> TestResult {
        let names: Vec<String> = parse_libalpm(input)?
            .iter()
            .map(|section| match section {
                Section::Base(_) => "Base".to_string(),
                Section::Desc(_) => "Desc".to_string(),
                Section::Groups(groups) => format!("Groups({})", groups.len()),
                Section::Data(data) => format!("Data({})", data.len()),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(names.join(" "), expected);
        Ok(())
    }

    /// Ensures that a malformed value of a known section is an error.
    #[test]
    fn libalpm_sections_fail_on_malformed_value() {
        assert!(parse_libalpm("%FOO%\nbar\n\n%CSIZE%\nnot a size\n").is_err());
    }
}
