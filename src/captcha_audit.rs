//! Separate trained output labels, observed labels, and a confirmed gateway alphabet.
use anyhow::{Context, Result, ensure};
use inode_cli::captcha_cnn::Model;
use serde::Serialize;
use std::{collections::BTreeSet, path::Path};

const CANDIDATES: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#[derive(Serialize)]
struct Audit {
    model_alphabet: String,
    candidate_alphabet: &'static str,
    candidate_characters_not_in_model: String,
    verified_sample_count: usize,
    observed_alphabet: String,
    observed_characters_not_in_model: String,
    expected_alphabet: Option<String>,
    expected_characters_not_in_model: Option<String>,
    gateway_alphabet_confirmed: bool,
    note: &'static str,
}

fn unique(s: &str) -> String {
    s.chars().collect::<BTreeSet<_>>().into_iter().collect()
}

fn missing(required: &str, model: &str) -> String {
    unique(required)
        .chars()
        .filter(|c| !model.contains(*c))
        .collect()
}

fn parse_labels(text: &str) -> Result<Vec<&str>> {
    let mut labels = Vec::new();
    for (index, line) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let code = line.trim();
        if code.is_empty() || code.starts_with('#') {
            continue;
        }
        ensure!(
            code.len() == 4 && code.chars().all(|c| CANDIDATES.contains(c)),
            "Invalid label on line {}: expected four uppercase ASCII letters/digits",
            index + 1
        );
        labels.push(code);
    }
    ensure!(!labels.is_empty(), "No human-verified labels in file");
    Ok(labels)
}

fn audit(model: &str, labels: &[&str], expected: Option<&str>) -> Result<Audit> {
    if let Some(expected) = expected {
        ensure!(
            !expected.is_empty() && expected.chars().all(|c| CANDIDATES.contains(c)),
            "Expected alphabet must contain uppercase ASCII letters/digits"
        );
        ensure!(
            labels
                .iter()
                .flat_map(|s| s.chars())
                .all(|c| expected.contains(c)),
            "Human-verified samples contain characters outside the expected alphabet"
        );
    }
    let observed = unique(&labels.concat());
    Ok(Audit {
        model_alphabet: model.to_owned(),
        candidate_alphabet: CANDIDATES,
        candidate_characters_not_in_model: missing(CANDIDATES, model),
        verified_sample_count: labels.len(),
        observed_characters_not_in_model: missing(&observed, model),
        observed_alphabet: observed,
        expected_alphabet: expected.map(unique),
        expected_characters_not_in_model: expected.map(|s| missing(s, model)),
        gateway_alphabet_confirmed: expected.is_some(),
        note: "Candidates are not confirmed gateway labels. Samples establish observed characters only. --expected is a caller-supplied confirmed alphabet, not automatic discovery. Missing classes require retraining; appending labels cannot add recognition ability.",
    })
}

pub fn run(labels_path: Option<&Path>, expected: Option<&str>) -> Result<()> {
    let text = labels_path
        .map(std::fs::read_to_string)
        .transpose()
        .context("Cannot read human-verified CAPTCHA labels")?;
    let labels = text
        .as_deref()
        .map(parse_labels)
        .transpose()?
        .unwrap_or_default();
    let report = audit(&Model::load().alphabet(), &labels, expected)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(
        report.observed_characters_not_in_model.is_empty()
            && report
                .expected_characters_not_in_model
                .as_ref()
                .is_none_or(String::is_empty),
        "Trained CAPTCHA model lacks required characters; retraining is necessary"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_missing_classes_do_not_disappear_behind_high_confidence() {
        let report = audit("19AN", &["9NMM", "1A59"], None).unwrap();
        assert_eq!(report.observed_characters_not_in_model, "5M");
        assert!(!report.gateway_alphabet_confirmed);
    }

    #[test]
    fn candidate_coverage_does_not_claim_full_gateway_coverage() {
        let report = audit("19AN", &[], None).unwrap();
        assert!(!report.gateway_alphabet_confirmed);
        assert!(report.expected_alphabet.is_none());
        assert!(report.observed_alphabet.is_empty());
    }

    #[test]
    fn confirmed_alphabet_must_agree_with_verified_samples() {
        assert!(audit("19AN", &["9NMM"], Some("19AN")).is_err());
        let report = audit("19AN", &["9NMM"], Some("19ANM")).unwrap();
        assert_eq!(
            report.expected_characters_not_in_model.as_deref(),
            Some("M")
        );
    }

    #[test]
    fn labels_require_explicit_four_character_answers() {
        assert_eq!(
            parse_labels("\u{feff}# reviewed\n9NMM\n\n1A59\n").unwrap(),
            ["9NMM", "1A59"]
        );
        assert!(parse_labels("9NMM 0.999").is_err());
        assert!(parse_labels("9nmm").is_err());
        assert!(parse_labels("# empty").is_err());
    }
}
