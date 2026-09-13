/// Classify gateway text without mistaking a future lockout warning for a current lockout.
pub fn authentication_error(message: &str) -> &'static str {
    let message = message.to_lowercase();
    if message.contains("验证码")
        || message.contains("verify")
        || message.contains("verification")
        || message.contains("vldcode")
    {
        "verification code rejected"
    } else if message.contains("will be locked") || message.contains("将被锁定") {
        "authentication failed; gateway warns that further failures may lock the account"
    } else if [
        "is locked",
        "has been locked",
        "temporarily locked",
        "已锁定",
        "已被锁定",
    ]
    .iter()
    .any(|s| message.contains(s))
    {
        "account or source is locked"
    } else {
        "authentication failed"
    }
}

/// Never echo arbitrary gateway text: it can include encoded credentials or cookies.
pub fn authentication_summary(message: &str) -> String {
    let mut summary = authentication_error(message).to_owned();
    let lower = message.to_lowercase();
    let count = lower
        .split_once("if another ")
        .and_then(|(_, tail)| {
            tail.strip_suffix(" login attempts fail, your account will be locked.")
        })
        .filter(|count| count.len() <= 3 && count.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|count| count.parse::<u16>().ok());
    if let Some(count) = count {
        summary.push_str(&format!(
            "; remaining failed attempts before lockout: {count}"
        ));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_recognized_lockout_count_is_reported() {
        let message =
            "Authentication failed. If another 1 login attempts fail, your account will be locked.";
        assert!(authentication_summary(message).ends_with("lockout: 1"));
        for untrusted in ["synthetic%26secret", "Cookie=synthetic-session", "123token"] {
            let message =
                format!("If another {untrusted} login attempts fail, your account will be locked.");
            assert!(!authentication_summary(&message).contains(untrusted));
        }
    }
}
