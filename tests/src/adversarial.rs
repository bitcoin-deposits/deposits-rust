//! Adversarial testing framework.
//!
//! Structured output for every attack: invariant tested, adversary capability,
//! cost, extraction, result, defense layer, scaling.

use std::fmt;

/// Which security property must hold to prevent this attack.
#[derive(Debug, Clone)]
pub enum Invariant {
    /// E1: reserves >= deposits at all times
    ReserveBacking,
    /// E2: collateral >= obligations backed
    CollateralBacking,
    /// E3: slashing >= maximum theft
    SlashingDeterrence,
    /// E4: expected value of attack < 0
    NegativeExpectedValue,
    /// C1: witness must satisfy descriptor
    WitnessValidity,
    /// C2: unique payment_hash (no double-credit)
    PaymentUniqueness,
    /// C3: signatures bound to (ledger, operation, context)
    SignatureBinding,
    /// C4: Taproot internal key is NUMS (unspendable)
    NUMSPoint,
    /// C5: Taproot tree matches announced quorum
    TaprootTreeIntegrity,
    /// S1: dispute state blocks normal operations
    DisputeStateGate,
    /// S2: hash chain append-only
    HashChainIntegrity,
    /// S3: balance cannot go negative
    BalanceNonNegative,
    /// S4: collateral locks ratchet-only
    CollateralRatchet,
    /// L1: disputes resolve in bounded time
    DisputeLiveness,
    /// L2: lottery completes even with withholding
    LotteryLiveness,
    /// L3: wallet can force evidence (DeliveryEmbed)
    WalletEmbedding,
    /// L4: relay censorship cannot suppress disputes
    RelayCensorshipResistance,
}

impl fmt::Display for Invariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReserveBacking => write!(f, "E1: reserves >= deposits"),
            Self::CollateralBacking => write!(f, "E2: collateral >= obligations"),
            Self::SlashingDeterrence => write!(f, "E3: slashing >= theft"),
            Self::NegativeExpectedValue => write!(f, "E4: EV(attack) < 0"),
            Self::WitnessValidity => write!(f, "C1: witness satisfies descriptor"),
            Self::PaymentUniqueness => write!(f, "C2: unique payment_hash"),
            Self::SignatureBinding => write!(f, "C3: signatures ledger-bound"),
            Self::NUMSPoint => write!(f, "C4: NUMS internal key"),
            Self::TaprootTreeIntegrity => write!(f, "C5: taproot tree matches quorum"),
            Self::DisputeStateGate => write!(f, "S1: dispute blocks normal ops"),
            Self::HashChainIntegrity => write!(f, "S2: append-only chain"),
            Self::BalanceNonNegative => write!(f, "S3: balance >= 0"),
            Self::CollateralRatchet => write!(f, "S4: collateral ratchet-only"),
            Self::DisputeLiveness => write!(f, "L1: bounded dispute resolution"),
            Self::LotteryLiveness => write!(f, "L2: lottery completion"),
            Self::WalletEmbedding => write!(f, "L3: wallet embed capability"),
            Self::RelayCensorshipResistance => write!(f, "L4: relay censorship resistance"),
        }
    }
}

/// What the attacker controls.
#[derive(Debug, Clone)]
pub struct AdversaryCapability {
    pub operators: usize,
    pub quorum_fraction: f64,
    pub controls_relay: bool,
    pub controls_miner: bool,
    pub computational_advantage: Option<String>,
}

impl fmt::Display for AdversaryCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} operator(s), {:.0}% quorum",
            self.operators,
            self.quorum_fraction * 100.0
        )?;
        if self.controls_relay {
            write!(f, ", relay control")?;
        }
        if self.controls_miner {
            write!(f, ", mining power")?;
        }
        if let Some(ref adv) = self.computational_advantage {
            write!(f, ", {}", adv)?;
        }
        Ok(())
    }
}

impl AdversaryCapability {
    pub fn single_operator(total_operators: usize) -> Self {
        Self {
            operators: 1,
            quorum_fraction: 1.0 / total_operators as f64,
            controls_relay: false,
            controls_miner: false,
            computational_advantage: None,
        }
    }

    pub fn operator_with_relay(total_operators: usize) -> Self {
        Self {
            operators: 1,
            quorum_fraction: 1.0 / total_operators as f64,
            controls_relay: true,
            controls_miner: false,
            computational_advantage: None,
        }
    }

    pub fn colluding(operators: usize, total_operators: usize) -> Self {
        Self {
            operators,
            quorum_fraction: operators as f64 / total_operators as f64,
            controls_relay: false,
            controls_miner: false,
            computational_advantage: None,
        }
    }
}

/// Where the defense operates.
#[derive(Debug, Clone, PartialEq)]
pub enum DefenseLayer {
    Protocol,
    Implementation,
    WalletPolicy,
    NodePolicy,
    Undefended,
}

impl fmt::Display for DefenseLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => write!(f, "protocol"),
            Self::Implementation => write!(f, "implementation"),
            Self::WalletPolicy => write!(f, "wallet-policy"),
            Self::NodePolicy => write!(f, "node-policy"),
            Self::Undefended => write!(f, "UNDEFENDED"),
        }
    }
}

/// How the attack cost scales.
#[derive(Debug, Clone)]
pub enum Scaling {
    Constant,
    Linear,
    SuperLinear,
}

impl fmt::Display for Scaling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Constant => write!(f, "constant"),
            Self::Linear => write!(f, "linear"),
            Self::SuperLinear => write!(f, "super-linear"),
        }
    }
}

/// What actually happened at each step of the attack.
#[derive(Debug, Clone)]
pub struct AttackStep {
    pub action: String,
    pub outcome: StepOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// Action succeeded (attacker progresses)
    Succeeded,
    /// Action was rejected by the protocol (Err returned)
    Rejected,
    /// Action succeeded but was detected by a watcher
    Detected,
    /// Action succeeded and was not detected
    Undetected,
    /// Not tested — model/analysis only
    Modeled,
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Succeeded => write!(f, "succeeded"),
            Self::Rejected => write!(f, "REJECTED"),
            Self::Detected => write!(f, "detected"),
            Self::Undetected => write!(f, "undetected"),
            Self::Modeled => write!(f, "modeled"),
        }
    }
}

/// Result of an adversarial test.
///
/// Use `AttackResult::new()` for the builder pattern, or construct directly
/// with `steps: vec![]` for tests that don't track steps.
pub struct AttackResult {
    pub name: String,
    pub invariant: Invariant,
    pub adversary: AdversaryCapability,
    pub cost_sats: u64,
    pub extraction_sats: u64,
    pub blocked: bool,
    pub defense: DefenseLayer,
    pub scaling: Scaling,
    pub notes: String,
    /// Step-by-step record of what happened.
    /// Empty for tests that don't track individual steps.
    #[doc(hidden)]
    pub steps: Vec<AttackStep>,
}

impl AttackResult {
    /// Convenience constructor — steps default to empty.
    pub fn build(
        name: impl Into<String>,
        invariant: Invariant,
        adversary: AdversaryCapability,
    ) -> AttackResultBuilder {
        AttackResultBuilder {
            name: name.into(),
            invariant,
            adversary,
            cost_sats: 0,
            extraction_sats: 0,
            blocked: true,
            defense: DefenseLayer::Protocol,
            scaling: Scaling::Constant,
            notes: String::new(),
            steps: Vec::new(),
        }
    }
}

pub struct AttackResultBuilder {
    name: String,
    invariant: Invariant,
    adversary: AdversaryCapability,
    cost_sats: u64,
    extraction_sats: u64,
    blocked: bool,
    defense: DefenseLayer,
    scaling: Scaling,
    notes: String,
    steps: Vec<AttackStep>,
}

impl AttackResultBuilder {
    pub fn cost(mut self, sats: u64) -> Self {
        self.cost_sats = sats;
        self
    }
    pub fn extraction(mut self, sats: u64) -> Self {
        self.extraction_sats = sats;
        self
    }
    pub fn blocked(mut self, b: bool) -> Self {
        self.blocked = b;
        self
    }
    pub fn defense(mut self, d: DefenseLayer) -> Self {
        self.defense = d;
        self
    }
    pub fn scaling(mut self, s: Scaling) -> Self {
        self.scaling = s;
        self
    }
    pub fn notes(mut self, n: impl Into<String>) -> Self {
        self.notes = n.into();
        self
    }
    pub fn step(
        mut self,
        action: impl Into<String>,
        outcome: StepOutcome,
        detail: impl Into<String>,
    ) -> Self {
        self.steps.push(AttackStep {
            action: action.into(),
            outcome,
            detail: detail.into(),
        });
        self
    }
    pub fn finish(self) -> AttackResult {
        AttackResult {
            name: self.name,
            invariant: self.invariant,
            adversary: self.adversary,
            cost_sats: self.cost_sats,
            extraction_sats: self.extraction_sats,
            blocked: self.blocked,
            defense: self.defense,
            scaling: self.scaling,
            notes: self.notes,
            steps: self.steps,
        }
    }
}

impl fmt::Display for AttackResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Attack: {}", self.name)?;
        writeln!(f, "  Invariant: {}", self.invariant)?;
        writeln!(f, "  Adversary: {}", self.adversary)?;
        writeln!(f, "  Cost: {} sats", self.cost_sats)?;
        writeln!(f, "  Extraction: {} sats", self.extraction_sats)?;
        if self.blocked {
            writeln!(f, "  Result: BLOCKED at {}", self.defense)?;
        } else {
            writeln!(f, "  Result: EXPLOITABLE (defense: {})", self.defense)?;
        }
        writeln!(f, "  Scales: {}", self.scaling)?;
        if !self.steps.is_empty() {
            writeln!(f, "  Steps:")?;
            for (i, step) in self.steps.iter().enumerate() {
                writeln!(
                    f,
                    "    {}. {} → {} ({})",
                    i + 1,
                    step.action,
                    step.outcome,
                    step.detail
                )?;
            }
        }
        if !self.notes.is_empty() {
            writeln!(f, "  Notes: {}", self.notes)?;
        }
        Ok(())
    }
}

/// Collect and report attack results.
pub struct AttackLog {
    pub results: Vec<AttackResult>,
}

impl Default for AttackLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackLog {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    pub fn record(&mut self, result: AttackResult) {
        println!("{}", result);
        self.results.push(result);
    }

    /// Return list of invariants that held (blocked attacks).
    pub fn invariants_that_held(&self) -> Vec<&Invariant> {
        self.results
            .iter()
            .filter(|r| r.blocked)
            .map(|r| &r.invariant)
            .collect()
    }

    /// Return list of exploitable findings.
    pub fn exploitable(&self) -> Vec<&AttackResult> {
        self.results.iter().filter(|r| !r.blocked).collect()
    }

    pub fn summary(&self) -> String {
        let blocked = self.results.iter().filter(|r| r.blocked).count();
        let exploitable = self.results.iter().filter(|r| !r.blocked).count();
        format!(
            "{} attacks tested: {} blocked, {} exploitable",
            self.results.len(),
            blocked,
            exploitable
        )
    }
}
