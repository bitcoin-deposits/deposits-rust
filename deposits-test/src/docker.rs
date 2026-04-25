//! Docker adversarial test environment.
//!
//! Provides a declarative spec for network topology and a control
//! interface for injecting operations and measuring profitability.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

/// Role of an operator in an adversarial test.
#[derive(Debug, Clone, PartialEq)]
pub enum Role {
    /// Follows protocol honestly.
    Honest,
    /// Controlled by the test — can inject arbitrary operations.
    Attacker,
    /// Honest but goes offline at a specified point.
    OfflineAfter { block_height: u32 },
}

/// Specification for one operator in the test network.
#[derive(Debug, Clone)]
pub struct OperatorSpec {
    pub name: String,
    pub reserves_sats: u64,
    pub role: Role,
}

/// How quorum membership is structured.
#[derive(Debug, Clone)]
pub enum QuorumSpec {
    /// Every operator backs every other operator.
    FullMesh,
    /// Specific membership pairs: (operator, member).
    Custom(Vec<(String, String)>),
}

/// Specification for a deposit in the initial state.
#[derive(Debug, Clone)]
pub struct DepositSpec {
    pub operator: String,
    pub amount_sats: u64,
    pub depositor: String,
}

/// Full network specification.
#[derive(Debug, Clone)]
pub struct NetworkSpec {
    pub operators: Vec<OperatorSpec>,
    pub quorum: QuorumSpec,
    pub collateral_per_member_sats: u64,
    pub enforcement_delay_blocks: u32,
    pub deposits: Vec<DepositSpec>,
}

impl NetworkSpec {
    /// Serialize to JSON for the shell harness.
    pub fn to_json(&self) -> String {
        let ops: Vec<String> = self
            .operators
            .iter()
            .map(|o| {
                format!(
                    "{{\"name\":\"{}\",\"reserves_sats\":{},\"role\":\"{}\"}}",
                    o.name,
                    o.reserves_sats,
                    match &o.role {
                        Role::Honest => "honest",
                        Role::Attacker => "attacker",
                        Role::OfflineAfter { .. } => "offline",
                    }
                )
            })
            .collect();
        format!(
            "{{\"operators\":[{}],\"default_reserves_sats\":{}}}",
            ops.join(","),
            self.operators
                .first()
                .map(|o| o.reserves_sats)
                .unwrap_or(100_000_000)
        )
    }
}

/// Balance sheet for one operator — tracks all fund positions.
#[derive(Debug, Clone, Default)]
pub struct BalanceSheet {
    /// On-chain reserves (sats)
    pub reserves_sats: u64,
    /// Total deposit balances on this operator's ledger (sats)
    pub deposit_balance_sats: u64,
    /// Collateral this operator has locked on OTHER ledgers (sats)
    pub collateral_locked_sats: u64,
    /// Collateral OTHER operators have locked backing this ledger (sats)
    pub collateral_backing_sats: u64,
    /// Wallet balance (non-reserves UTXOs, sats)
    pub wallet_balance_sats: u64,
}

impl BalanceSheet {
    /// Net position: what the operator controls minus what they owe.
    pub fn net_position(&self) -> i64 {
        (self.reserves_sats + self.wallet_balance_sats) as i64 - self.deposit_balance_sats as i64
    }

    /// Profit relative to a starting position.
    pub fn profit(&self, starting: &BalanceSheet) -> i64 {
        self.net_position() - starting.net_position()
    }
}

/// Handle to a running test environment.
pub struct TestEnvironment {
    pub spec: NetworkSpec,
    pub repo_root: PathBuf,
    pub running: bool,
    starting_balances: HashMap<String, BalanceSheet>,
}

impl TestEnvironment {
    pub fn new(spec: NetworkSpec) -> Self {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        Self {
            spec,
            repo_root,
            running: false,
            starting_balances: HashMap::new(),
        }
    }

    /// Start the Docker environment.
    pub fn start(&mut self) -> Result<(), String> {
        let harness = self.repo_root.join("tests/docker/harness.sh");
        let spec_json = self.spec.to_json();

        let output = Command::new("bash")
            .arg(&harness)
            .arg("start")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(spec_json.as_bytes()).ok();
                }
                child.wait_with_output()
            })
            .map_err(|e| format!("Failed to start harness: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Harness failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        self.running = true;

        // Record starting balances
        for op in &self.spec.operators {
            self.starting_balances
                .insert(op.name.clone(), self.query_balance(&op.name));
        }

        Ok(())
    }

    /// Stop the environment.
    pub fn stop(&mut self) {
        let harness = self.repo_root.join("tests/docker/harness.sh");
        let _ = Command::new("bash").arg(&harness).arg("stop").output();
        self.running = false;
    }

    /// Get a control handle for one operator.
    pub fn control(&self, name: &str) -> NodeControl {
        let op = self
            .spec
            .operators
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("operator '{}' not in spec", name));

        NodeControl {
            name: name.to_string(),
            repo_root: self.repo_root.clone(),
            role: op.role.clone(),
        }
    }

    /// Query the current balance sheet for an operator.
    pub fn query_balance(&self, name: &str) -> BalanceSheet {
        let tools_dir = self.repo_root.join("deposits-tools");
        let output = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "source {}/bin/_common.sh && init_topology && run_node_cmd {} info 2>/dev/null",
                tools_dir.display(),
                name
            ))
            .output()
            .ok();

        let info = output
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        // Parse reserves and deposits from info output
        let reserves = extract_number(&info, "reserves").unwrap_or(0);
        let deposits = extract_number(&info, "total").unwrap_or(0);

        BalanceSheet {
            reserves_sats: reserves,
            deposit_balance_sats: deposits,
            ..Default::default()
        }
    }

    /// Get profit/loss for an operator relative to start.
    pub fn profit(&self, name: &str) -> i64 {
        let current = self.query_balance(name);
        let starting = self
            .starting_balances
            .get(name)
            .cloned()
            .unwrap_or_default();
        current.profit(&starting)
    }

    /// Mine N blocks.
    pub fn mine_blocks(&self, n: u32) {
        let _ = Command::new("docker")
            .args([
                "exec",
                "bitcoind",
                "bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=pass",
                "-generate",
                &n.to_string(),
            ])
            .output();
        // Wait for electrs to index
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        if self.running {
            self.stop();
        }
    }
}

/// Control handle for injecting operations into a specific node.
pub struct NodeControl {
    pub name: String,
    pub repo_root: PathBuf,
    pub role: Role,
}

impl NodeControl {
    /// Run a CLI command on this node.
    pub fn run_cmd(&self, args: &[&str]) -> Result<String, String> {
        let tools_dir = self.repo_root.join("deposits-tools");
        let cmd_str = format!(
            "source {}/bin/_common.sh && init_topology && run_node_cmd {} {}",
            tools_dir.display(),
            self.name,
            args.join(" ")
        );

        let output = Command::new("bash")
            .arg("-c")
            .arg(&cmd_str)
            .output()
            .map_err(|e| e.to_string())?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Get this node's ledger ID.
    pub fn ledger_id(&self) -> Option<String> {
        let output = self.run_cmd(&["ledger", "list"]).ok()?;
        output
            .lines()
            .find(|l| l.contains("Ledger ID:"))
            .and_then(|l| {
                l.split_whitespace()
                    .find(|w| w.len() >= 48 && w.chars().all(|c| c.is_ascii_hexdigit()))
            })
            .map(|s| s.to_string())
    }

    /// Get this node's info.
    pub fn info(&self) -> Result<String, String> {
        self.run_cmd(&["info"])
    }

    /// Get reserves list.
    pub fn reserves(&self) -> Result<String, String> {
        self.run_cmd(&["reserves", "list"])
    }
}

fn extract_number(text: &str, keyword: &str) -> Option<u64> {
    text.lines()
        .find(|l| l.to_lowercase().contains(keyword))
        .and_then(|l| {
            l.split_whitespace()
                .filter_map(|w| w.replace(',', "").parse::<u64>().ok())
                .next()
        })
}

/// Search for the boundary at which an attack becomes profitable.
///
/// Binary search over a parameter (e.g., collateral ratio, expiry window)
/// to find the threshold where attacker profit flips from negative to positive.
pub struct InvariantBoundarySearch {
    pub parameter_name: String,
    pub min_value: f64,
    pub max_value: f64,
    pub precision: f64,
}

impl InvariantBoundarySearch {
    pub fn new(name: &str, min: f64, max: f64, precision: f64) -> Self {
        Self {
            parameter_name: name.to_string(),
            min_value: min,
            max_value: max,
            precision,
        }
    }

    /// Run the search. `test_fn` returns the attacker's profit for a given parameter value.
    /// Negative = deterred, positive = profitable.
    ///
    /// Automatically detects whether profit increases or decreases with the parameter
    /// and searches accordingly.
    pub fn find_boundary(&self, mut test_fn: impl FnMut(f64) -> f64) -> f64 {
        let mut lo = self.min_value;
        let mut hi = self.max_value;

        // Detect direction: is profit higher at min or max?
        let profit_at_lo = test_fn(lo);
        let profit_at_hi = test_fn(hi);
        let profit_decreases = profit_at_lo > profit_at_hi;

        while (hi - lo) > self.precision {
            let mid = (lo + hi) / 2.0;
            let profit = test_fn(mid);
            if profit_decreases {
                // Profit is high at lo, low at hi — find where it crosses zero
                if profit > 0.0 {
                    lo = mid; // still profitable, boundary is higher
                } else {
                    hi = mid; // deterred, boundary is lower
                }
            } else {
                // Profit is low at lo, high at hi — find where it crosses zero
                if profit < 0.0 {
                    lo = mid; // still deterred, boundary is higher
                } else {
                    hi = mid; // profitable, boundary is lower
                }
            }
        }

        (lo + hi) / 2.0
    }
}
