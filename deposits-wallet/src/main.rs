//! Deposits Wallet - A Nostr-based wallet for depositors
//!
//! Discovers ledger operators, opens deposits, and manages balances.
//!
//! Usage:
//!   deposits-wallet discover                   - Find available ledgers
//!   deposits-wallet open <ledger_id> <sats>    - Open a new deposit
//!   deposits-wallet offer <alias> <sats>       - Add funds to existing deposit
//!   deposits-wallet list                       - List deposits with aliases
//!   deposits-wallet balance                    - Check balances
//!   deposits-wallet withdraw <alias> <amount>  - Withdraw funds (on-chain)
//!   deposits-wallet make_invoice <alias> <amt> - Create Lightning invoice
//!   deposits-wallet pay_invoice <alias> <bolt11> - Pay Lightning invoice

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod wallet_cli;

use wallet_cli::print_usage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls 0.23+ won't auto-pick a CryptoProvider even with a single
    // feature enabled — the first wss:// handshake panics. Install
    // `ring` here, before any relay connection. Idempotent.
    deposits_nostr::install_default_crypto_provider();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "discover" => wallet_cli::discover::discover(&args[2..]).await,
        "info" => wallet_cli::discover::ledger_info(&args[2..]).await,
        "open" => wallet_cli::deposit::open_new_deposit(&args[2..]).await,
        "offer" => wallet_cli::deposit::add_offer(&args[2..]).await,
        "balance" => wallet_cli::deposit::show_balance(&args[2..]).await,
        "sync" => wallet_cli::deposit::sync_deposits(&args[2..]).await,
        "withdraw" => wallet_cli::payments::withdraw(&args[2..]).await,
        "transfer" => wallet_cli::payments::transfer_lock(&args[2..]).await,
        "transfer_complete" => wallet_cli::payments::transfer_complete(&args[2..]).await,
        "escalate" => wallet_cli::escalate::escalate(&args[2..]).await,
        "send" => wallet_cli::payments::send(&args[2..]).await,
        "attest" => wallet_cli::attest::attest_subkey(&args[2..]).await,
        "revoke" => wallet_cli::attest::revoke_subkey(&args[2..]).await,
        "subkeys" => wallet_cli::attest::list_subkeys(&args[2..]).await,
        "swap-advertise" => wallet_cli::swap::swap_advertise(&args[2..]).await,
        "swap-list" => wallet_cli::swap::swap_list(&args[2..]).await,
        "swap-request" => wallet_cli::swap::swap_request(&args[2..]).await,
        "swap-listen" => wallet_cli::swap::swap_listen(&args[2..]).await,
        "route" => wallet_cli::payments::route_transfer(&args[2..]).await,
        "spread" => wallet_cli::payments::spread_deposits(&args[2..]).await,
        "batch" => wallet_cli::batch::batch_mode(&args[2..]).await,
        "make_invoice" => wallet_cli::payments::make_invoice(&args[2..]).await,
        "pay_invoice" => wallet_cli::payments::pay_invoice(&args[2..]).await,
        "history" => wallet_cli::payments::show_history(&args[2..]).await,
        "list" => wallet_cli::deposit::list_deposits(&args[2..]).await,
        "ledger" => wallet_cli::ledger::ledger_command(&args[2..]).await,
        "regtest-faucet" => wallet_cli::regtest::faucet(&args[2..]).await,
        "help" | "--help" | "-h" => {
            print_usage(&args[0]);
            Ok(())
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            print_usage(&args[0]);
            Ok(())
        }
    }
}
