#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

impl Auth {
    pub fn new(user: impl Into<String>, pass: impl Into<String>) -> Self {
        Self {
            username: user.into(),
            password: pass.into(),
        }
    }

    pub fn verify(&self, user: &str, pass: &str) -> bool {
        self.username == user && self.password == pass
    }

    pub fn verify_basic(&self, header_value: &str) -> bool {
        let rest = header_value.trim();
        let b64 = if let Some(s) = rest.strip_prefix("Basic ").or_else(|| rest.strip_prefix("basic ")) {
            s.trim()
        } else {
            return false;
        };

        let decoded = match base64_decode(b64) {
            Some(d) => d,
            None => return false,
        };

        let s = match std::str::from_utf8(&decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match s.split_once(':') {
            Some((u, p)) => self.verify(u, p),
            None => false,
        }
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;

    for &byte in input.as_bytes() {
        let val: u8 = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        Auth::new("user", "pass")
    }

    #[test]
    fn test_verify_correct() {
        assert!(auth().verify("user", "pass"));
    }

    #[test]
    fn test_verify_wrong_password() {
        assert!(!auth().verify("user", "wrong"));
    }

    #[test]
    fn test_verify_wrong_user() {
        assert!(!auth().verify("admin", "pass"));
    }

    #[test]
    fn test_verify_empty() {
        assert!(!auth().verify("", ""));
        assert!(!Auth::new("", "").verify("user", "pass"));
    }

    #[test]
    fn test_verify_case_sensitive() {
        assert!(!auth().verify("User", "Pass"));
    }

    #[test]
    fn test_verify_basic_correct() {
        assert!(auth().verify_basic("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_verify_basic_lowercase_prefix() {
        assert!(auth().verify_basic("basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_verify_basic_wrong_password() {
        assert!(!auth().verify_basic("Basic dXNlcjp3cm9uZw=="));
    }

    #[test]
    fn test_verify_basic_no_prefix() {
        assert!(!auth().verify_basic("dXNlcjpwYXNz"));
    }

    #[test]
    fn test_verify_basic_empty() {
        assert!(!auth().verify_basic(""));
        assert!(!auth().verify_basic("Basic "));
    }

    #[test]
    fn test_verify_basic_no_colon() {
        assert!(!auth().verify_basic("Basic dXNlcnBhc3M="));
    }

    #[test]
    fn test_verify_basic_password_with_colon() {
        let a = Auth::new("user", "p:ass");
        assert!(a.verify_basic("Basic dXNlcjpwOmFzcw=="));
    }

    #[test]
    fn test_verify_basic_with_padding_whitespace() {
        assert!(auth().verify_basic("Basic  dXNlcjpwYXNz "));
    }

    #[test]
    fn test_base64_decode_standard() {
        assert_eq!(base64_decode("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
    }

    #[test]
    fn test_base64_decode_with_padding() {
        assert_eq!(base64_decode("dXNlcjp3cm9uZw=="), Some(b"user:wrong".to_vec()));
    }

    #[test]
    fn test_base64_decode_empty() {
        assert_eq!(base64_decode(""), Some(vec![]));
    }

    #[test]
    fn test_base64_decode_invalid_char() {
        assert_eq!(base64_decode("!!!"), None);
    }
}
