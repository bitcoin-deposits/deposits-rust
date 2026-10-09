//! DEP-20 §3 exit addresses: standard output types and their dust floors, pinned by the
//! vector shared with cl-deposits (`tests/vectors/exit_address.txt`, cl-generated).

use deposits_protocol::types::{dust_floor_sats, spk_type, standard_output};

#[test]
fn exit_address_types_and_dust_floors_match_the_shared_vector() {
    let text = include_str!("vectors/exit_address.txt");
    let mut n = 0;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let first = line.find(' ').unwrap();
        let last = line.rfind(' ').unwrap();
        let spk = hex::decode(&line[..first]).unwrap();
        let ty = &line[first + 1..last];
        let floor: u64 = line[last + 1..].parse().unwrap();
        n += 1;
        if ty == "invalid" {
            assert!(
                spk_type(&spk).is_none(),
                "{} must not be a standard exit",
                line
            );
        } else {
            assert_eq!(
                format!("{:?}", spk_type(&spk).unwrap()).to_lowercase(),
                ty,
                "{}",
                line
            );
            assert_eq!(dust_floor_sats(&spk), Some(floor), "{}", line);
            assert!(standard_output(&spk, floor) && !standard_output(&spk, floor - 1));
        }
    }
    assert_eq!(n, 12);
}
