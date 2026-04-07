//! Input normalization and sanitization.
//!
//! All external input (bridge messages, session output) passes through
//! this module before processing. Strips invisible Unicode characters
//! that could be used for prompt injection or spoofing, and detects
//! mixed-script text (potential homoglyph attacks).

use std::sync::LazyLock;

use regex::Regex;

/// The result of normalizing a text input.
#[derive(Clone, Debug)]
pub struct NormalizeResult {
    /// The cleaned text with invisible characters removed.
    pub cleaned: String,
    /// How many characters were stripped.
    pub stripped_count: usize,
    /// What categories of characters were stripped or flagged.
    pub categories: Vec<String>,
}

/// Strip ANSI escape sequences from terminal output.
///
/// This is applied to session output before `ToolAdapter::parse_output()`.
/// Handles:
/// - CSI sequences (colors, cursor movement, scroll, etc.)
/// - OSC sequences (operating system commands, title setting)
/// - Simple two-byte escape sequences
/// - Character set selection (`\x1b(B`, etc.)
pub fn strip_ansi(input: &str) -> String {
    static ANSI_RE: LazyLock<Regex> = LazyLock::new(|| {
        // Order matters: longer patterns first so the alternation is greedy.
        // 1. CSI sequences: ESC [ <params> <intermediates> <final byte>
        // 2. OSC sequences: ESC ] ... (ST or BEL)
        // 3. Character set selection: ESC ( <char>  /  ESC ) <char>
        // 4. Simple two-byte escapes: ESC <0x40..0x5F>
        Regex::new(concat!(
            r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]", // CSI
            r"|\x1b\].*?(?:\x1b\\|\x07)",                 // OSC
            r"|\x1b[()][A-Z0-9]",                         // charset select
            r"|\x1b[\x40-\x5f]",                          // simple escape
        ))
        .unwrap_or_else(|_| {
            #[allow(clippy::expect_used)]
            Regex::new("").expect("empty regex is infallible")
        })
    });

    ANSI_RE.replace_all(input, "").into_owned()
}

/// Normalize text by stripping invisible characters and flagging suspicious
/// patterns.
///
/// This function:
/// - Strips zero-width characters (U+200B..U+200D, U+FEFF)
/// - Strips invisible Unicode tag characters (U+E0001..U+E007F)
/// - Strips directional overrides (U+202A..U+202E, U+2066..U+2069)
/// - Strips control characters except `\n` and `\t`
/// - Strips variation selectors (U+FE00..U+FE0F)
/// - Detects (but does not strip) mixed-script words (Latin + Cyrillic)
pub fn normalize_text(input: &str) -> NormalizeResult {
    let mut cleaned = String::with_capacity(input.len());
    let mut stripped_count: usize = 0;
    let mut categories: Vec<String> = Vec::new();

    for ch in input.chars() {
        if is_zero_width(ch) {
            stripped_count += 1;
            add_category(&mut categories, "zero-width");
        } else if is_tag_character(ch) {
            stripped_count += 1;
            add_category(&mut categories, "tag-character");
        } else if is_directional_override(ch) {
            stripped_count += 1;
            add_category(&mut categories, "directional-override");
        } else if is_variation_selector(ch) {
            stripped_count += 1;
            add_category(&mut categories, "variation-selector");
        } else if is_control_character(ch) {
            stripped_count += 1;
            add_category(&mut categories, "control-character");
        } else {
            cleaned.push(ch);
        }
    }

    // Detect mixed-script words (flag but don't strip).
    if has_mixed_script_words(&cleaned) {
        add_category(&mut categories, "mixed-script");
    }

    NormalizeResult {
        cleaned,
        stripped_count,
        categories,
    }
}

/// Zero-width characters used for invisible text injection.
fn is_zero_width(ch: char) -> bool {
    matches!(ch, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}')
}

/// Unicode tag characters (U+E0001..U+E007F), used for invisible tagging.
fn is_tag_character(ch: char) -> bool {
    ('\u{E0001}'..='\u{E007F}').contains(&ch)
}

/// Bidirectional text overrides that can reorder displayed text.
fn is_directional_override(ch: char) -> bool {
    // U+202A..U+202E: embedding/override/pop
    // U+2066..U+2069: isolate/pop
    ('\u{202A}'..='\u{202E}').contains(&ch) || ('\u{2066}'..='\u{2069}').contains(&ch)
}

/// Variation selectors that modify glyph rendering.
fn is_variation_selector(ch: char) -> bool {
    ('\u{FE00}'..='\u{FE0F}').contains(&ch)
}

/// Control characters, excluding newline and tab which are legitimate.
fn is_control_character(ch: char) -> bool {
    ch.is_control() && ch != '\n' && ch != '\t'
}

/// Add a category to the list if not already present.
fn add_category(categories: &mut Vec<String>, category: &str) {
    if !categories.iter().any(|c| c == category) {
        categories.push(category.into());
    }
}

/// Detect words that mix Latin and Cyrillic characters (homoglyph risk).
///
/// For example, "password" where 'a' is Cyrillic U+0430 instead of
/// Latin 'a' U+0061.
fn has_mixed_script_words(text: &str) -> bool {
    // The word regex is infallible (simple pattern), and the fallback
    // empty regex is equally infallible. Using `ok()` + `unwrap_or`
    // avoids both `unwrap` and `expect`.
    static WORD_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b\w+\b").unwrap_or_else(|_| {
            // An empty pattern matches everything; this branch is
            // unreachable in practice but satisfies the no-panic lint.
            #[allow(clippy::expect_used)]
            Regex::new("").expect("empty regex is infallible")
        })
    });

    for m in WORD_RE.find_iter(text) {
        let word = m.as_str();
        let has_latin = word.chars().any(is_latin);
        let has_cyrillic = word.chars().any(is_cyrillic);
        if has_latin && has_cyrillic {
            return true;
        }
    }
    false
}

fn is_latin(ch: char) -> bool {
    // Basic Latin letters + Latin Extended-A/B.
    matches!(ch, 'A'..='Z' | 'a'..='z' | '\u{00C0}'..='\u{024F}')
}

fn is_cyrillic(ch: char) -> bool {
    // Cyrillic block U+0400..U+04FF.
    ('\u{0400}'..='\u{04FF}').contains(&ch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_text_passes_through_unchanged() {
        let result = normalize_text("Hello, world! 123");
        assert_eq!(result.cleaned, "Hello, world! 123");
        assert_eq!(result.stripped_count, 0);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn preserves_newlines_and_tabs() {
        let input = "line one\n\tindented line two\n";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, input);
        assert_eq!(result.stripped_count, 0);
    }

    #[test]
    fn strips_zero_width_characters() {
        // U+200B (zero-width space) injected into "hello"
        let input = "hel\u{200B}lo";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "hello");
        assert_eq!(result.stripped_count, 1);
        assert!(result.categories.contains(&"zero-width".into()));
    }

    #[test]
    fn strips_byte_order_mark() {
        let input = "\u{FEFF}Hello";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "Hello");
        assert_eq!(result.stripped_count, 1);
        assert!(result.categories.contains(&"zero-width".into()));
    }

    #[test]
    fn strips_directional_overrides() {
        // U+202E (right-to-left override)
        let input = "normal \u{202E}reversed";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "normal reversed");
        assert_eq!(result.stripped_count, 1);
        assert!(result.categories.contains(&"directional-override".into()));
    }

    #[test]
    fn strips_tag_characters() {
        // U+E0001 (language tag)
        let input = "test\u{E0001}text";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "testtext");
        assert_eq!(result.stripped_count, 1);
        assert!(result.categories.contains(&"tag-character".into()));
    }

    #[test]
    fn strips_variation_selectors() {
        let input = "text\u{FE0F}more";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "textmore");
        assert_eq!(result.stripped_count, 1);
        assert!(result.categories.contains(&"variation-selector".into()));
    }

    #[test]
    fn strips_control_characters_except_newline_tab() {
        // U+0000 (null), U+0007 (bell), but keep \n and \t
        let input = "hello\x00world\x07\nok\tok";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "helloworld\nok\tok");
        assert_eq!(result.stripped_count, 2);
        assert!(result.categories.contains(&"control-character".into()));
    }

    #[test]
    fn detects_mixed_script_latin_cyrillic() {
        // "pаssword" with Cyrillic 'а' (U+0430) instead of Latin 'a'.
        let input = "p\u{0430}ssword";
        let result = normalize_text(input);
        // The text itself is unchanged (mixed-script is flagged, not stripped).
        assert_eq!(result.cleaned, input);
        assert_eq!(result.stripped_count, 0);
        assert!(result.categories.contains(&"mixed-script".into()));
    }

    #[test]
    fn pure_cyrillic_is_not_flagged_as_mixed() {
        // Pure Cyrillic word: "привет" (hello)
        let input = "\u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, input);
        assert!(result.categories.is_empty());
    }

    #[test]
    fn multiple_categories_tracked() {
        let input = "\u{200B}\u{202E}\u{FE0F}clean";
        let result = normalize_text(input);
        assert_eq!(result.cleaned, "clean");
        assert_eq!(result.stripped_count, 3);
        assert!(result.categories.contains(&"zero-width".into()));
        assert!(result.categories.contains(&"directional-override".into()));
        assert!(result.categories.contains(&"variation-selector".into()));
    }

    #[test]
    fn empty_input_returns_empty() {
        let result = normalize_text("");
        assert_eq!(result.cleaned, "");
        assert_eq!(result.stripped_count, 0);
        assert!(result.categories.is_empty());
    }

    // ── strip_ansi tests ──────────────────────────────────────────

    #[test]
    fn ansi_strips_color_codes() {
        assert_eq!(strip_ansi("\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn ansi_strips_cursor_movement() {
        assert_eq!(strip_ansi("\x1b[2J\x1b[H"), "");
    }

    #[test]
    fn ansi_preserves_plain_text() {
        assert_eq!(strip_ansi("hello world"), "hello world");
    }

    #[test]
    fn ansi_strips_mixed_content() {
        assert_eq!(
            strip_ansi("\x1b[1mbold\x1b[0m normal \x1b[32mgreen\x1b[0m"),
            "bold normal green"
        );
    }

    #[test]
    fn ansi_strips_osc_sequences() {
        assert_eq!(strip_ansi("\x1b]0;title\x07text"), "text");
    }

    #[test]
    fn ansi_empty_input_returns_empty() {
        assert_eq!(strip_ansi(""), "");
    }

    #[test]
    fn ansi_strips_sgr_charset_selection() {
        // \x1b(B is a common "reset to ASCII" escape.
        assert_eq!(strip_ansi("\x1b(Bhello"), "hello");
    }

    #[test]
    fn ansi_strips_osc_with_st_terminator() {
        // OSC terminated by ST (ESC \) instead of BEL.
        assert_eq!(strip_ansi("\x1b]2;window title\x1b\\content"), "content");
    }
}
