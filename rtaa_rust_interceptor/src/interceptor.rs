//! Untrusted Aggregator & Theorem 1 Identity-Weight Relabeling Attack Simulation
//! Strictly implements the paper's threat model (Sections 3 & 5.1):
//! The adversary is the UNTRUSTED AGGREGATOR itself, which receives authentic reports
//! from reporting nodes and maliciously permutes/swaps their algebraic weights.

use crate::packet::NetworkAuthPacket;
use crate::protocol::AuthReport;
use crate::crypto::fr_to_hex;

pub struct AggregatorChannel {
    pub received_reports: Vec<NetworkAuthPacket>,
}

impl AggregatorChannel {
    pub fn new() -> Self {
        Self {
            received_reports: Vec::new(),
        }
    }

    /// Aggregator receives an authentic telemetry packet from a sensor node
    pub fn receive_packet(&mut self, pkt: NetworkAuthPacket) {
        self.received_reports.push(pkt);
    }

    /// Honest Aggregator: Compiles and submits reports untouched to the Verifier
    pub fn submit_honest(&self, verbose: bool) -> Vec<AuthReport> {
        if verbose {
            println!("[AGGREGATOR] Honest mode: Forwarding {} reports untouched to Central Verifier.", self.received_reports.len());
        }
        self.received_reports
            .iter()
            .map(AuthReport::from_packet)
            .collect()
    }

    /// Malicious Aggregator (Theorem 1 Identity-Weight Relabeling Attack):
    /// The untrusted Aggregator receives valid reports from target_a and target_b,
    /// but maliciously swaps their claimed weights w_a <-> w_b when presenting the claim to the Verifier.
    /// Invariant: sum(w_i) mod q is preserved, fooling the linear consistency check!
    pub fn mount_theorem1_relabeling_attack(
        &self,
        target_a: &[u8],
        target_b: &[u8],
        verbose: bool,
    ) -> (Vec<AuthReport>, usize, usize) {
        if verbose {
            println!();
            println!("================================================================================");
            println!(" [!] MALICIOUS AGGREGATOR ATTACK (THEOREM 1 IDENTITY-WEIGHT RELABELING)");
            println!("     Paper Threat Model: The Aggregator itself is the untrusted adversary.");
            println!("================================================================================");
            println!("[*] Aggregator received legitimate reports from all registered nodes.");
        }

        let mut tampered = self.received_reports.clone();
        let idx_a = tampered
            .iter()
            .position(|p| p.source_node_id == target_a)
            .expect("Target node A not found in aggregator");
        let idx_b = tampered
            .iter()
            .position(|p| p.source_node_id == target_b)
            .expect("Target node B not found in aggregator");

        if verbose {
            println!("[+] Received Report from Node [{}]:", String::from_utf8_lossy(&tampered[idx_a].source_node_id));
            tampered[idx_a].display_inspection("GENUINE REPORT A (RECEIVED BY AGGREGATOR)");

            println!("[+] Received Report from Node [{}]:", String::from_utf8_lossy(&tampered[idx_b].source_node_id));
            tampered[idx_b].display_inspection("GENUINE REPORT B (RECEIVED BY AGGREGATOR)");
        }

        // Save original weights
        let w_a_orig = tampered[idx_a].claimed_weight;
        let w_b_orig = tampered[idx_b].claimed_weight;

        if verbose {
            println!();
            println!("[!] EXECUTING THEOREM 1 ATTACK (MALICIOUS AGGREGATOR RELABELING):");
            println!("    - Authentic Weight A (Alice): 0x{}...", &fr_to_hex(&w_a_orig)[..32]);
            println!("    - Authentic Weight B (Bob):   0x{}...", &fr_to_hex(&w_b_orig)[..32]);
            println!("    --> Action: Aggregator swaps claimed weights w_Alice <---> w_Bob in the aggregate claim!");
        }

        // Malicious Aggregator swaps the weights
        tampered[idx_a].claimed_weight = w_b_orig;
        tampered[idx_b].claimed_weight = w_a_orig;

        if verbose {
            println!("    [+] Submitting Weight for Alice: 0x{}...", &fr_to_hex(&tampered[idx_a].claimed_weight)[..32]);
            println!("    [+] Submitting Weight for Bob:   0x{}...", &fr_to_hex(&tampered[idx_b].claimed_weight)[..32]);
            println!("    [+] INVARIANT: (w_A + w_B) mod q == (w_B + w_A) mod q (Sum is IDENTICAL!)");
            println!("    --> Malicious Aggregator submits tampered aggregate to Central Verifier...");
            println!("================================================================================");
            println!();
        }

        let reports = tampered.iter().map(AuthReport::from_packet).collect();
        (reports, idx_a, idx_b)
    }
}
