//! Lexical path normalization for policy-facing context fields.
//!
//! This deliberately does not touch the filesystem. It only gives Cedar rules a
//! stable string view across Windows/POSIX separator and case variants.

pub(crate) fn normalize_path_value(path: &str) -> String {
    let stripped = path
        .strip_prefix("\\\\?\\")
        .or_else(|| path.strip_prefix("\\\\.\\"))
        .unwrap_or(path);

    let mut normalized = String::with_capacity(stripped.len());
    let mut last_was_slash = false;
    for ch in stripped.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' {
            if !last_was_slash {
                normalized.push('/');
                last_was_slash = true;
            }
            continue;
        }
        last_was_slash = false;
        for lower in ch.to_lowercase() {
            normalized.push(lower);
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::normalize_path_value;

    #[test]
    fn normalizes_windows_prefix_separators_repeats_and_case() {
        assert_eq!(
            normalize_path_value(r"\\?\C:\Users\Alice\\.AWS\credentials"),
            "c:/users/alice/.aws/credentials"
        );
        assert_eq!(
            normalize_path_value(r"\\.\C:\Temp\\SONDERA.EXE"),
            "c:/temp/sondera.exe"
        );
    }

    #[test]
    fn normalization_is_lexical_and_preserves_traversal_markers() {
        assert_eq!(
            normalize_path_value(r"..\Users\Alice\..\Secrets"),
            "../users/alice/../secrets"
        );
        assert_eq!(normalize_path_value("~/Project/.ENV"), "~/project/.env");
    }
}
