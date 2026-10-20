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
    for (label, patterns) in [
        (
            "invalid credentials",
            &[
                "username or password",
                "user name or password",
                "用户名或密码",
                "invalid password",
                "incorrect password",
            ][..],
        ),
        (
            "password change required",
            &[
                "change password",
                "change your password",
                "password has expired",
                "修改密码",
                "密码已过期",
            ][..],
        ),
        (
            "authentication server unavailable",
            &["authentication server", "radius server", "认证服务器"][..],
        ),
        ("password", &["password", "密码"][..]),
        ("expired", &["expired", "过期"][..]),
        ("disabled", &["disabled", "禁用"][..]),
        (
            "concurrent",
            &["already online", "already logged", "concurrent", "同时在线"][..],
        ),
        (
            "policy",
            &["not allowed", "permission", "denied", "无权限"][..],
        ),
    ] {
        if patterns.iter().any(|p| lower.contains(p)) {
            summary.push_str(&format!("; gateway mentions {label}"));
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_message_is_not_lost_or_confused_with_sensitive_fields() {
        for tag in [
            "message",
            "replyMessage",
            "errorMsg",
            "ErrorMessage",
            "reason",
        ] {
            let body = format!(
                "<data><result>Failed</result><{tag}>Invalid password</{tag}><cookie>synthetic-secret</cookie></data>"
            );
            let doc = roxmltree::Document::parse(&body).unwrap();
            let message = response_message(&doc);
            assert!(authentication_summary(&message).contains("gateway mentions password"));
            assert!(!message.contains("synthetic-secret"));
        }
        let doc = roxmltree::Document::parse(
            "<data><message>Verification code rejected</message></data>",
        )
        .unwrap();
        assert_eq!(
            authentication_error(&response_message(&doc)),
            "verification code rejected"
        );
    }

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
pub(super) fn response_message(doc: &roxmltree::Document<'_>) -> String {
    doc.descendants()
        .filter(|n| n.is_element())
        .filter(|n| {
            [
                "replymessage",
                "errormsg",
                "errormessage",
                "message",
                "reason",
                "result",
                "type",
            ]
            .contains(&n.tag_name().name().to_ascii_lowercase().as_str())
        })
        .filter_map(|n| n.text())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}
