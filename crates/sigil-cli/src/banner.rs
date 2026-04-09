//! ASCII banner for sigil CLI branding.

/// ASCII art banner displayed on conductor startup.
pub const BANNER: &str = "\
     _       _ _
 ___(_) __ _(_) |
/ __| |/ _` | | |
\\__ \\ | (_| | | |
|___/_|\\__, |_|_|
       |___/";

/// Long version string shown by `sigil --version`.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n\n",
    "     _       _ _\n",
    " ___(_) __ _(_) |\n",
    "/ __| |/ _` | | |\n",
    "\\__ \\ | (_| | | |\n",
    "|___/_|\\__, |_|_|\n",
    "       |___/",
);
