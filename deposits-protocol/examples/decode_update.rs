//! Read base64 kind:9100 event contents (one per line) on stdin; print each
//! update's inner op type + whether it carries a DEP-02 balance commitment.
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;
use std::io::BufRead;

fn commitment_str(op: &LedgerOperation) -> String {
    use LedgerOperation as O;
    macro_rules! c { ($c:expr) => { match $c { Some(b)=>format!("commit(bal={},lock={})", b.balance_after, b.locked_after), None=>"NO-COMMIT".into() } } }
    match op {
        O::DepositOpen{commitment,..}|O::DepositClose{commitment,..}|O::FeeCollect{commitment,..}
        |O::InvoiceCredit{commitment,..}|O::InvoiceLock{commitment,..}|O::InvoiceFail{commitment,..}
        |O::InvoiceFulfill{commitment,..}|O::OnchainCredit{commitment,..}|O::OnchainLock{commitment,..}
        |O::OnchainFail{commitment,..}|O::OnchainFulfill{commitment,..}|O::TransferLock{commitment,..}
        |O::TransferFail{commitment,..} => c!(commitment),
        O::TransferComplete{commitment,dest_commitment,..} => format!("{} dest={}", c!(commitment), c!(dest_commitment)),
        _ => "n/a (not balance-touching)".into(),
    }
}
fn opname(op:&LedgerOperation)->&'static str{ use LedgerOperation as O; match op {
    O::LedgerOpen{..}=>"LedgerOpen",O::QuorumBegin{..}=>"QuorumBegin",O::QuorumAddMember{..}=>"QuorumAddMember",
    O::QuorumRemoveMember{..}=>"QuorumRemoveMember",O::QuorumJoin{..}=>"QuorumJoin",O::QuorumUpgrade{..}=>"QuorumUpgrade",
    O::DepositOpen{..}=>"DepositOpen",O::DepositClose{..}=>"DepositClose",O::DepositKeyRotate{..}=>"DepositKeyRotate",
    O::FeeChange{..}=>"FeeChange",O::FeeCollect{..}=>"FeeCollect",O::InvoiceCredit{..}=>"InvoiceCredit",
    O::InvoiceLock{..}=>"InvoiceLock",O::InvoiceFail{..}=>"InvoiceFail",O::InvoiceFulfill{..}=>"InvoiceFulfill",
    O::OnchainCredit{..}=>"OnchainCredit",O::OnchainLock{..}=>"OnchainLock",O::OnchainFail{..}=>"OnchainFail",
    O::OnchainFulfill{..}=>"OnchainFulfill",O::TransferLock{..}=>"TransferLock",O::TransferComplete{..}=>"TransferComplete",
    O::TransferFail{..}=>"TransferFail",O::DisputeEnter{..}=>"DisputeEnter",O::DisputeAcquire{..}=>"DisputeAcquire",
    O::DisputeYield=>"DisputeYield",O::DisputeArmed{..}=>"DisputeArmed",O::DeliveryEmbed{..}=>"DeliveryEmbed",
    O::LedgerClose=>"LedgerClose",O::Batch(_)=>"Batch",
}}
fn main(){
    for line in std::io::stdin().lock().lines().map_while(Result::ok){
        let line=line.trim(); if line.is_empty(){continue}
        let Ok(bytes)=hex::decode(line) else { println!("  <hex decode failed>"); continue };
        let Ok(u)=SignedLedgerUpdate::tlv_decode(&bytes) else { println!("  <update decode failed>"); continue };
        match LedgerOperation::tlv_decode(&u.message){
            Ok(op)=>println!("  seq={:>4} {:20} {}", u.sequence_number, opname(&op), commitment_str(&op)),
            Err(e)=>println!("  seq={:>4} <op decode failed: {:?}>", u.sequence_number, e),
        }
    }
}
