use crate::config::Redaction;
use regex::Regex;
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Debug, Default, serde::Serialize, Clone)]
pub struct Summary {
    #[serde(skip_serializing_if = "is_zero")]
    pub token: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub email: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ip_address: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub authorization_header: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub private_key: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub path: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub custom: u64,
}
fn is_zero(x: &u64) -> bool {
    *x == 0
}
impl Summary {
    pub fn total(&self) -> u64 {
        self.token
            + self.email
            + self.ip_address
            + self.authorization_header
            + self.private_key
            + self.path
            + self.custom
    }
}

pub struct Engine {
    config: Redaction,
    ids: BTreeMap<String, usize>,
    summary: Summary,
}
impl Engine {
    pub fn new(config: &Redaction) -> Self {
        Self {
            config: Redaction {
                privacy_level: match config.privacy_level {
                    crate::config::PrivacyLevel::Strict => crate::config::PrivacyLevel::Strict,
                    crate::config::PrivacyLevel::Standard => crate::config::PrivacyLevel::Standard,
                    crate::config::PrivacyLevel::Custom => crate::config::PrivacyLevel::Custom,
                },
                emails: config.emails,
                ip_addresses: config.ip_addresses,
                paths: config.paths,
                custom_patterns: config.custom_patterns.clone(),
            },
            ids: BTreeMap::new(),
            summary: Summary::default(),
        }
    }
    fn replace_selected<F>(
        &mut self,
        re: &Regex,
        text: String,
        class: &str,
        should_replace: F,
    ) -> (String, u64)
    where
        F: Fn(&str) -> bool,
    {
        let mut result = String::new();
        let mut previous = 0;
        let mut count = 0;
        for m in re.find_iter(&text) {
            if !should_replace(m.as_str()) {
                continue;
            }
            result.push_str(&text[previous..m.start()]);
            let raw = m.as_str().to_string();
            let next = self.ids.len() + 1;
            let id = *self.ids.entry(format!("{class}:{raw}")).or_insert(next);
            result.push_str(&format!("<REDACTED:{class}_{id}>"));
            previous = m.end();
            count += 1;
        }
        result.push_str(&text[previous..]);
        (result, count)
    }
    fn replace_stable(&mut self, re: &Regex, text: String, class: &str) -> String {
        self.replace_selected(re, text, class, |_| true).0
    }
    pub fn sanitize(&mut self, data: &[u8]) -> Vec<u8> {
        let mut s = String::from_utf8_lossy(data).into_owned();
        let rules: [(&str, &str); 7] = [
            (
                "authorization_header",
                r"(?im)^(authorization\s*:\s*)(?:bearer\s+)?[^\r\n]+",
            ),
            (
                "private_key",
                r"(?s)-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
            ),
            (
                "token",
                r"(?i)\b(?:bearer\s+)?eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
            ),
            ("token", r"\bAKIA[0-9A-Z]{16}\b"),
            (
                "token",
                r#"(?i)(?:api[_-]?key|token|secret|password|session(?:_token)?|cookie)\s*[=:]\s*[^\s,;\"']{8,}"#,
            ),
            (
                "token",
                r"(?i)(?:https?://[^\s?]+\?[^\s#]*(?:token|key|secret|password)=[^\s&#]+)",
            ),
            (
                "email",
                r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b",
            ),
        ];
        for (class, pattern) in rules {
            if class == "email" && !self.config.emails {
                continue;
            }
            let re = Regex::new(pattern).unwrap();
            let count = re.find_iter(&s).count() as u64;
            if count == 0 {
                continue;
            }
            s = self.replace_stable(&re, s, &class.to_ascii_uppercase());
            match class {
                "authorization_header" => self.summary.authorization_header += count,
                "private_key" => self.summary.private_key += count,
                "email" => self.summary.email += count,
                _ => self.summary.token += count,
            }
        }
        if self.config.ip_addresses {
            // Candidate matching is deliberately broader than an IPv6 regex; parsing
            // with the standard library handles compressed and IPv4-mapped IPv6 forms.
            let re = Regex::new(r"(?i)[0-9a-f:.]{2,}").unwrap();
            let (replaced, count) = self.replace_selected(&re, s, "IP_ADDRESS", |candidate| {
                candidate.trim_end_matches('.').parse::<IpAddr>().is_ok()
            });
            s = replaced;
            if count > 0 {
                self.summary.ip_address += count;
            }
        }
        if self.config.paths {
            let re =
                Regex::new(r"(?i)[a-z]:\\Users\\[^\\/\s]+|/home/[^/\s]+|/Users/[^/\s]+").unwrap();
            let count = re.find_iter(&s).count() as u64;
            if count > 0 {
                s = self.replace_stable(&re, s, "USER");
                self.summary.path += count;
            }
        }
        for pat in self.config.custom_patterns.clone() {
            let re = Regex::new(&pat).unwrap();
            let count = re.find_iter(&s).count() as u64;
            if count > 0 {
                s = self.replace_stable(&re, s, "CUSTOM");
                self.summary.custom += count;
            }
        }
        s.into_bytes()
    }
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Redaction;
    #[test]
    fn removes_known_secrets_and_keeps_correlations() {
        let mut e = Engine::new(&Redaction::default());
        let source = b"Authorization: Bearer secret-value-12345678\na@b.example a@b.example\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\nAKIAIOSFODNN7EXAMPLE";
        let got = String::from_utf8(e.sanitize(source)).unwrap();
        for value in [
            "secret-value-12345678",
            "a@b.example",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(!got.contains(value));
        }
        assert_eq!(got.matches("REDACTED:EMAIL_").count(), 2);
    }

    #[test]
    fn generated_api_key_values_never_survive() {
        for n in 0..128 {
            let secret = format!("api_key=fixture-secret-{n:03}-abcdefghijk");
            let mut engine = Engine::new(&Redaction::default());
            let result = String::from_utf8(engine.sanitize(secret.as_bytes())).unwrap();
            assert!(!result.contains(&secret), "secret {n} survived redaction");
        }
    }

    #[test]
    fn redacts_compressed_ipv6_addresses() {
        let mut engine = Engine::new(&Redaction::default());
        let result =
            String::from_utf8(engine.sanitize(b"remote=2001:db8::1 mapped=::ffff:192.0.2.1"))
                .unwrap();
        assert!(!result.contains("2001:db8::1"));
        assert!(!result.contains("::ffff:192.0.2.1"));
        assert_eq!(engine.summary().ip_address, 2);
    }

    #[test]
    fn redacts_ipv4_before_sentence_punctuation() {
        let mut engine = Engine::new(&Redaction::default());
        let result = String::from_utf8(engine.sanitize(b"remote=203.0.113.42.")).unwrap();
        assert!(!result.contains("203.0.113.42"));
        assert_eq!(engine.summary().ip_address, 1);
    }
}
