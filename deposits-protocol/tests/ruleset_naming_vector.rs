//! DEP-18 ruleset naming, shared with cl-deposits (`tests/vectors/ruleset_naming.txt`):
//! rulesets are named, not ordered. Seating and upgrade verdicts are consensus; the
//! planned name is the reference operator policy.

use deposits_protocol::types::{planned_ruleset, seat_verdict, upgrade_verdict, RulesetVerdict};

fn ruleset(s: &str) -> String {
    if s == "-" {
        String::new()
    } else {
        s.to_string()
    }
}

fn declarations(s: &str) -> Vec<Vec<String>> {
    s.split(';')
        .map(|m| {
            if m == "-" {
                Vec::new()
            } else {
                m.split(',').map(str::to_string).collect()
            }
        })
        .collect()
}

fn verdict(s: &str) -> RulesetVerdict {
    match s {
        "ok" => RulesetVerdict::Ok,
        "unknown" => RulesetVerdict::Unknown,
        "family" => RulesetVerdict::Family,
        "unsupported" => RulesetVerdict::Unsupported,
        other => panic!("unknown verdict {other}"),
    }
}

#[test]
fn ruleset_naming_vector() {
    let text = include_str!("vectors/ruleset_naming.txt");
    let mut n = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "seat" => assert_eq!(
                seat_verdict(f[1], &declarations(f[2])),
                verdict(f[3]),
                "{line}"
            ),
            "upgrade" => assert_eq!(
                upgrade_verdict(&ruleset(f[1]), f[2], &declarations(f[3])),
                verdict(f[4]),
                "{line}"
            ),
            "plan" => assert_eq!(
                planned_ruleset(&ruleset(f[1]), &declarations(f[2])),
                f[3],
                "{line}"
            ),
            other => panic!("unknown case {other}"),
        }
        n += 1;
    }
    assert_eq!(n, 21);
}
