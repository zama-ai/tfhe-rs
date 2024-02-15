use crate::utils::project_root;
use std::io::{Error, ErrorKind};
use std::{fmt, fs};

fn recurse_find_rs_files(
    root_dir: std::path::PathBuf,
    rs_files: &mut Vec<std::path::PathBuf>,
    at_root: bool,
) {
    for curr_entry in root_dir.read_dir().unwrap() {
        let curr_path = curr_entry.unwrap().path().canonicalize().unwrap();
        if curr_path.is_file() {
            if let Some(extension) = curr_path.extension() {
                if extension == "rs" {
                    rs_files.push(curr_path);
                }
            }
        } else if curr_path.is_dir() {
            if at_root {
                // Hardcoded ignores for root .git and target
                match curr_path.file_name().unwrap().to_str().unwrap() {
                    ".git" => continue,
                    "target" => continue,
                    _ => recurse_find_rs_files(curr_path.to_path_buf(), rs_files, false),
                };
            } else {
                recurse_find_rs_files(curr_path.to_path_buf(), rs_files, false);
            }
        }
    }
}

#[derive(Debug)]
struct LatexEscapeToolError {
    details: String,
}

impl LatexEscapeToolError {
    fn new(msg: &str) -> LatexEscapeToolError {
        LatexEscapeToolError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for LatexEscapeToolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for LatexEscapeToolError {}

const DOC_TEST_START: &str = "///";
const DOC_COMMENT_START: &str = "//!";
const BACKSLASH_UTF8_LEN: usize = '\\'.len_utf8();

enum LineType {
    DocTest { code_block_limit: bool },
    DocComment { code_block_limit: bool },
    EmptyLine,
    Other,
}

fn get_line_type_and_trimmed_line(line: &str) -> (LineType, &str) {
    let mut trimmed_line = line.trim_start();
    let line_type = if trimmed_line.starts_with(DOC_COMMENT_START) {
        trimmed_line = trimmed_line
            .strip_prefix(DOC_COMMENT_START)
            .unwrap()
            .trim_start();
        let has_code_block_limit = trimmed_line.starts_with("```");
        LineType::DocComment {
            code_block_limit: has_code_block_limit,
        }
    } else if trimmed_line.starts_with(DOC_TEST_START) {
        trimmed_line = trimmed_line
            .strip_prefix(DOC_TEST_START)
            .unwrap()
            .trim_start();
        let has_code_block_limit = trimmed_line.starts_with("```");
        LineType::DocTest {
            code_block_limit: has_code_block_limit,
        }
    } else if trimmed_line.is_empty() {
        LineType::EmptyLine
    } else {
        LineType::Other
    };
    (line_type, trimmed_line)
}

struct CommentContent<'a> {
    is_in_code_block: bool,
    line_start: &'a str,
    line_content: &'a str,
}

fn find_contiguous_doc_comment<'a>(
    lines: &[&'a str],
    start_line_idx: usize,
) -> (Vec<CommentContent<'a>>, usize) {
    let mut doc_comment_end_line_idx = start_line_idx + 1;

    let mut is_in_code_block = false;
    let mut contiguous_doc_comment = Vec::<CommentContent>::new();

    for (line_idx, line) in lines.iter().enumerate().skip(start_line_idx) {
        let (line_type, line_content) = get_line_type_and_trimmed_line(line);

        let line_start = &line[..line.len() - line_content.len()];
        // If there is an empty line we are still in the DocComment
        let line_type = if let LineType::EmptyLine = line_type {
            LineType::DocComment {
                code_block_limit: false,
            }
        } else {
            line_type
        };

        match line_type {
            LineType::DocComment { code_block_limit } => {
                if code_block_limit {
                    // We have found a code block limit, either starting or ending, toggle the
                    // flag
                    is_in_code_block = !is_in_code_block;
                };
                contiguous_doc_comment.push(CommentContent {
                    is_in_code_block,
                    line_start,
                    line_content,
                });
                // For now the only thing we know is that the next line is potentially the end of
                // the comment block, required if a file is a giant comment block to have the proper
                // bound
                doc_comment_end_line_idx = line_idx + 1;
            }
            _ => {
                // We are sure that the current line is the end of the comment block
                doc_comment_end_line_idx = line_idx;
                break;
            }
        };
    }
    (contiguous_doc_comment, doc_comment_end_line_idx)
}

fn find_contiguous_doc_test<'a>(
    lines: &[&'a str],
    start_line_idx: usize,
) -> (Vec<CommentContent<'a>>, usize) {
    let mut doc_test_end_line_idx = start_line_idx + 1;

    let mut is_in_code_block = false;
    let mut contiguous_doc_test = Vec::<CommentContent>::new();

    for (line_idx, line) in lines.iter().enumerate().skip(start_line_idx) {
        let (line_type, line_content) = get_line_type_and_trimmed_line(line);

        let line_start = &line[..line.len() - line_content.len()];
        // If there is an empty line we are still in the DocTest
        let line_type = if let LineType::EmptyLine = line_type {
            LineType::DocTest {
                code_block_limit: false,
            }
        } else {
            line_type
        };

        match line_type {
            LineType::DocTest { code_block_limit } => {
                if code_block_limit {
                    // We have found a code block limit, either starting or ending, toggle the
                    // flag
                    is_in_code_block = !is_in_code_block;
                };
                contiguous_doc_test.push(CommentContent {
                    is_in_code_block,
                    line_start,
                    line_content,
                });
                // For now the only thing we know is that the next line is potentially the end of
                // the comment block, required if a file is a giant comment block to have the proper
                // bound
                doc_test_end_line_idx = line_idx + 1;
            }
            _ => {
                // We are sure that the current line is the end of the comment block
                doc_test_end_line_idx = line_idx;
                break;
            }
        };
    }
    (contiguous_doc_test, doc_test_end_line_idx)
}

fn find_contiguous_part_in_doc_test_or_comment(
    part_is_code_block: bool,
    full_doc_comment_content: &[CommentContent],
    part_start_idx: usize,
) -> (usize, usize) {
    let mut next_line_idx = part_start_idx + 1;
    loop {
        // We have exhausted the doc comment content, break
        if next_line_idx == full_doc_comment_content.len() {
            break;
        }

        let CommentContent {
            is_in_code_block: next_line_is_in_code_block,
            line_start: _,
            line_content: _,
        } = full_doc_comment_content[next_line_idx];

        // We check if the next line is in a different part, if so we break
        if next_line_is_in_code_block != part_is_code_block {
            break;
        }
        next_line_idx += 1;
    }
    // next_line_idx points to the end of the part and is therefore returned as the part_stop_idx
    (part_start_idx, next_line_idx)
}

enum LatexEquationKind {
    Inline,
    Multiline,
    NotAnEquation,
}

fn escape_underscores_rewrite_equations(
    comment_to_rewrite: &[CommentContent],
    rewritten_content: &mut String,
) -> Result<(), LatexEscapeToolError> {
    let mut latex_equation_kind = LatexEquationKind::NotAnEquation;
    for CommentContent {
        is_in_code_block: _,
        line_start,
        line_content,
    } in comment_to_rewrite.iter()
    {
        rewritten_content.push_str(line_start);
        let mut previous_char = '\0';
        let mut chars = line_content.chars().peekable();
        while let Some(current_char) = chars.next() {
            match (previous_char, current_char) {
                ('$', '$') => {
                    match latex_equation_kind {
                        LatexEquationKind::Inline => {
                            // Problem we find an opening $$ after an opening $, return an error
                            return Err(LatexEscapeToolError::new(
                                "Found an opening '$' without a corresponding closing '$'",
                            ));
                        }
                        LatexEquationKind::Multiline => {
                            // Closing $$, no more in a latex equation
                            latex_equation_kind = LatexEquationKind::NotAnEquation
                        }
                        LatexEquationKind::NotAnEquation => {
                            // Opening $$, in a multiline latex equation
                            latex_equation_kind = LatexEquationKind::Multiline
                        }
                    };
                }
                (_, '$') => {
                    let is_inline_marker = chars.peek() != Some(&'$');
                    if is_inline_marker {
                        match latex_equation_kind {
                            LatexEquationKind::Multiline => {
                                // Problem we find an opening $ after an opening $$, return an error
                                return Err(LatexEscapeToolError::new(
                                    "Found an opening '$$' without a corresponding closing '$$'",
                                ));
                            }
                            LatexEquationKind::Inline => {
                                // Closing $, no more in a latex equation
                                latex_equation_kind = LatexEquationKind::NotAnEquation
                            }
                            LatexEquationKind::NotAnEquation => {
                                // Opening $, in an inline latex equation
                                latex_equation_kind = LatexEquationKind::Inline
                            }
                        };
                    }
                    // If the marker is not an inline marker but a multiline marker let the other
                    // case manage it at the next iteration
                }
                // If the _ is not escaped and we are in an equation we need to escape it
                (prev, '_') if prev != '\\' => match latex_equation_kind {
                    LatexEquationKind::NotAnEquation => (),
                    _ => rewritten_content.push('\\'),
                },
                _ => (),
            }
            rewritten_content.push(current_char);
            previous_char = current_char;
        }
    }
    Ok(())
}

fn process_doc_lines_until_impossible<'a>(
    lines: &[&'a str],
    rewritten_content: &'a mut String,
    comment_search_fn: fn(&[&'a str], usize) -> (Vec<CommentContent<'a>>, usize),
    start_line_idx: usize,
) -> Result<usize, LatexEscapeToolError> {
    let (full_doc_content, doc_end_line_idx) = comment_search_fn(lines, start_line_idx);

    // Now we find code blocks parts OR pure comments parts
    let mut current_line_in_doc_idx = 0;
    while current_line_in_doc_idx < full_doc_content.len() {
        let CommentContent {
            is_in_code_block,
            line_start: _,
            line_content: _,
        } = full_doc_content[current_line_in_doc_idx];

        let (current_part_start_idx, current_part_stop_idx) =
            find_contiguous_part_in_doc_test_or_comment(
                is_in_code_block,
                &full_doc_content,
                current_line_in_doc_idx,
            );

        let current_part_content = &full_doc_content[current_part_start_idx..current_part_stop_idx];

        // The current part is a code block
        if is_in_code_block {
            for CommentContent {
                is_in_code_block: _,
                line_start,
                line_content,
            } in current_part_content.iter()
            {
                // We can just push the content unmodified
                rewritten_content.push_str(line_start);
                rewritten_content.push_str(line_content);
            }
        } else {
            // The part is a pure comment, we need to rewrite equations
            escape_underscores_rewrite_equations(current_part_content, rewritten_content)?;
        }
        current_line_in_doc_idx += current_part_content.len();
    }

    Ok(doc_end_line_idx)
}

fn process_non_doc_lines_until_impossible(
    lines: &[&str],
    rewritten_content: &mut String,
    mut line_idx: usize,
) -> usize {
    while line_idx < lines.len() {
        let line = lines[line_idx];
        match get_line_type_and_trimmed_line(line) {
            (LineType::Other, _) => {
                rewritten_content.push_str(line);
                line_idx += 1;
            }
            _ => break,
        };
    }
    line_idx
}

fn escape_underscore_in_latex_doc_in_file(
    file_path: &std::path::Path,
) -> Result<(), LatexEscapeToolError> {
    let file_name = file_path.to_str().unwrap();
    let content = std::fs::read_to_string(file_name).unwrap();

    let number_of_underscores = content.matches('_').count();
    let potential_additional_capacity_required = number_of_underscores * BACKSLASH_UTF8_LEN;

    // Enough for the length of the original string + the length if we had to escape *all* `_`
    // which won't happen but avoids reallocations
    let mut rewritten_content =
        String::with_capacity(content.len() + potential_additional_capacity_required);

    let content_by_lines: Vec<&str> = content.split_inclusive('\n').collect();
    let mut line_idx = 0_usize;

    while line_idx < content_by_lines.len() {
        let line = content_by_lines[line_idx];
        let (line_type, _) = get_line_type_and_trimmed_line(line);
        line_idx = match line_type {
            LineType::DocComment {
                code_block_limit: _,
            } => process_doc_lines_until_impossible(
                &content_by_lines,
                &mut rewritten_content,
                find_contiguous_doc_comment,
                line_idx,
            )?,
            LineType::DocTest {
                code_block_limit: _,
            } => process_doc_lines_until_impossible(
                &content_by_lines,
                &mut rewritten_content,
                find_contiguous_doc_test,
                line_idx,
            )?,
            LineType::Other => process_non_doc_lines_until_impossible(
                &content_by_lines,
                &mut rewritten_content,
                line_idx,
            ),
            LineType::EmptyLine => {
                rewritten_content.push_str(line);
                line_idx + 1
            }
        };
    }

    fs::write(file_name, rewritten_content).unwrap();
    Ok(())
}

pub fn escape_underscore_in_latex_doc() -> Result<(), Error> {
    let project_root = project_root();
    let mut src_files: Vec<std::path::PathBuf> = Vec::new();
    recurse_find_rs_files(project_root, &mut src_files, true);

    println!("Found {} files to process.", src_files.len());

    let mut files_with_problems: Vec<(std::path::PathBuf, LatexEscapeToolError)> = Vec::new();

    println!("Processing...");
    for file in src_files.into_iter() {
        if let Err(err) = escape_underscore_in_latex_doc_in_file(&file) {
            files_with_problems.push((file, err));
        }
    }
    println!("Done!");

    if !files_with_problems.is_empty() {
        for (file_with_problem, error) in files_with_problems.iter() {
            println!(
                "File: {}, has error: {}",
                file_with_problem.display(),
                error
            );
        }
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Issues while processing files, check log.",
        ));
    }

    Ok(())
}
