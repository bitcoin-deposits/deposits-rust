//! The DEP-06 subset lottery, pinned for cl-deposits to reproduce
//! (inspect/vectors/lottery_subsets.txt there). Participants have secrets
//! `[i; 32]` and commitments `[i; 20]`; voters are 21..=23 at threshold 2;
//! signet. `REGEN_VECTORS=1` rewrites the file.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use deposits_core::tapscript_reserves::{
    build_armer_share_output, LotteryOutput, LotteryParticipant, LotteryScriptBuilder,
};

fn xonly(seed: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

fn render() -> String {
    let mut lines = Vec::new();
    let voters = vec![xonly(21), xonly(22), xonly(23)];
    for k in [1usize, 2, 3, 7] {
        let mut participants: Vec<LotteryParticipant> = (1..=k as u8)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        participants.sort_by_key(|a| a.pubkey.serialize());
        let out = LotteryScriptBuilder::new(participants, voters.clone(), 2, Network::Signet)
            .build()
            .unwrap();
        lines.push(format!(
            "VEC k={} full={}",
            k,
            hex::encode(out.lottery_script.as_bytes())
        ));
        lines.push(format!("VEC k={} address={}", k, out.address));
        lines.push(format!(
            "VEC k={} control_full={}",
            k,
            hex::encode(out.lottery_control_block().unwrap().serialize())
        ));
        lines.push(format!(
            "VEC k={} recovery144={}",
            k,
            hex::encode(out.recovery_leaves()[0].2.as_bytes())
        ));
        lines.push(format!("VEC k={} subsets={}", k, out.subset_scripts.len()));
        let n = out.subset_scripts.len();
        for pos in [0, n / 2, n.saturating_sub(1)] {
            if let Some((idx, leaf)) = out.subset_scripts.get(pos) {
                let name = idx
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                lines.push(format!(
                    "VEC k={} subset[{}]={}",
                    k,
                    name,
                    hex::encode(leaf.as_bytes())
                ));
                lines.push(format!(
                    "VEC k={} control[{}]={}",
                    k,
                    name,
                    hex::encode(out.subset_control_block(idx).unwrap().serialize())
                ));
            }
        }
    }
    // Winner table: lengths per member of S, and the winning participant index.
    let cases: [(&[usize], &[usize]); 5] = [
        (&[0, 1, 2, 3, 4, 5, 6], &[17, 76, 40, 23, 61, 18, 50]),
        (&[0, 2, 5], &[20, 76, 33]),
        (&[1, 3, 4, 6], &[76, 76, 76, 76]),
        (&[4], &[29]),
        (&[0, 1, 2, 3, 5, 6], &[17, 18, 19, 20, 21, 22]),
    ];
    for (idx, lens) in cases {
        let pre: Vec<Vec<u8>> = lens.iter().map(|&l| vec![0u8; l]).collect();
        let w = LotteryOutput::subset_winner(idx, &pre).unwrap();
        let s = |v: &[usize]| {
            v.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        lines.push(format!("VEC winner[{}]({})={}", s(idx), s(lens), w));
    }
    for i in 0u32..4 {
        let seed = sha256::Hash::hash(&i.to_be_bytes()).to_byte_array();
        lines.push(format!(
            "VEC preimage[{}]={}",
            i,
            hex::encode(LotteryOutput::derive_lottery_preimage(&seed))
        ));
    }
    let share =
        build_armer_share_output(&xonly(1), &[1u8; 20], &voters, 2, Network::Signet).unwrap();
    lines.push(format!("VEC armer_share={}", share.address));
    lines.join("\n") + "\n"
}

#[test]
fn lottery_subset_vector_is_pinned() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/lottery_subsets.txt"
    );
    let now = render();
    if std::env::var("REGEN_VECTORS").is_ok() {
        std::fs::write(path, &now).unwrap();
    }
    let pinned = std::fs::read_to_string(path).expect("vector file (REGEN_VECTORS=1 to create)");
    assert_eq!(now, pinned);
}
