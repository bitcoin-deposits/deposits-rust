//! DEP-07 FeeCollect cap, pinned by the vector shared with cl-deposits
//! (`tests/vectors/fees_due.txt`, cl-generated).

use deposits_protocol::types::{Deposit, FeeStructure};

#[test]
fn fees_due_match_the_shared_vector() {
    let text = include_str!("vectors/fees_due.txt");
    let mut n = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let v: Vec<u128> = line.split(' ').map(|x| x.parse().unwrap()).collect();
        let mut d = Deposit::new(
            "pk(00)".to_string(),
            Some(FeeStructure {
                annualized_msats: v[1] as u64,
                annualized_bps: v[2] as u16,
                frequency_blocks: v[3] as u32,
            }),
        );
        d.balance = v[0] as u64;
        d.last_fee_assessment = v[4] as u32;
        assert_eq!(d.calculate_fees_due(v[5] as u32) as u128, v[6], "{}", line);
        n += 1;
    }
    assert_eq!(n, 8);
}
