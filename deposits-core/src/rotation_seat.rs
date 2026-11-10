//! DEP-11 §Rotating without a silent member (ruled 2026-11-10): which consenting members an
//! operator seats when it rotates without the silent ones. Operator policy, not a consensus rule
//! (validators check only the `QuorumBegin` itself), but both implementations seat the same set.
//! Pinned by `tests/vectors/rotation_seat.json`, shared with cl-deposits.

/// The members to seat, from `staged` (the consenting members, in the order they consented):
/// those seated now (`current`) first, then the newcomers, each group in consent order, cut to
/// the largest valid quorum size (3, 5 or 7). `None` with fewer than three consents.
pub fn seat_consenting<T: PartialEq + Clone>(current: &[T], staged: &[T]) -> Option<Vec<T>> {
    let mut order: Vec<T> = staged.iter().filter(|m| current.contains(m)).cloned().collect();
    order.extend(staged.iter().filter(|m| !current.contains(m)).cloned());
    let size = crate::VALID_QUORUM_SIZES
        .iter()
        .copied()
        .filter(|&q| q <= order.len())
        .max()?;
    order.truncate(size);
    Some(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seat_consenting_matches_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/rotation_seat.json")).unwrap();
        let strs = |a: &serde_json::Value| -> Vec<String> {
            a.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 6);
        for c in cases {
            let got = seat_consenting(&strs(&c["current"]), &strs(&c["staged"]));
            let want = if c["seat"].is_null() {
                None
            } else {
                Some(strs(&c["seat"]))
            };
            assert_eq!(got, want, "{}", c["name"]);
        }
    }
}
