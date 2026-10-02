// Throwaway: print lottery-script vectors for cl-deposits to compare against.
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Network;
use deposits_core::tapscript_reserves::{
    build_armer_share_output, LotteryParticipant, LotteryScriptBuilder,
};

fn xonly(seed: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
    let secp = Secp256k1::new();
    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
        .x_only_public_key()
        .0
}

#[test]
fn print_vectors() {
    for n in [3usize, 6] {
        let mut participants: Vec<LotteryParticipant> = (1..=n as u8)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        participants.sort_by_key(|a| a.pubkey.serialize());
        let voters = vec![xonly(21), xonly(22), xonly(23)];
        let b = LotteryScriptBuilder::new(participants, voters.clone(), 2, Network::Signet);
        let out = b.build().unwrap();
        println!(
            "VEC n={} script={}",
            n,
            hex::encode(out.lottery_script.as_bytes())
        );
        println!(
            "VEC n={} partial0={}",
            n,
            hex::encode(out.partial_reveal_scripts[0].as_bytes())
        );
        println!(
            "VEC n={} recovery144={}",
            n,
            hex::encode(out.recovery_leaves()[0].2.as_bytes())
        );
        println!("VEC n={} address={}", n, out.address);
        println!(
            "VEC n={} control0={}",
            n,
            hex::encode(out.lottery_control_block().unwrap().serialize())
        );
        let share =
            build_armer_share_output(&xonly(1), &[1u8; 20], &voters, 2, Network::Signet).unwrap();
        println!("VEC n={} armer_share={}", n, share.address);
    }
}
