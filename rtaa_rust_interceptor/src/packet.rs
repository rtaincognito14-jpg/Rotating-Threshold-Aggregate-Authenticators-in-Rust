//! Network Packet Definitions & Serialization
//! Simulates real edge sensor node network payloads over untrusted channels.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_serialize::CanonicalSerialize;
use crate::crypto::{fr_to_hex, g1_to_hex, g2_to_hex};

/// Represents an authentic report packet in-transit across the network
#[derive(Clone, Debug)]
pub struct NetworkAuthPacket {
    pub source_node_id: Vec<u8>,
    pub source_ip: String,
    pub round_r: u64,
    pub payload_vector: Vec<Fr>,
    pub claimed_weight: Fr,
    pub base_tag: G1Affine,
    pub audit_tag: Option<G1Affine>,
    pub public_key: G2Affine,
}

impl NetworkAuthPacket {
    /// Serialize packet to raw binary wire-format bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // 1. Source Node ID length + bytes
        bytes.extend_from_slice(&(self.source_node_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.source_node_id);

        // 2. IP string length + bytes
        let ip_bytes = self.source_ip.as_bytes();
        bytes.extend_from_slice(&(ip_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(ip_bytes);

        // 3. Round r
        bytes.extend_from_slice(&self.round_r.to_be_bytes());

        // 4. Payload vector count + elements
        bytes.extend_from_slice(&(self.payload_vector.len() as u32).to_be_bytes());
        for val in &self.payload_vector {
            val.serialize_compressed(&mut bytes).unwrap();
        }

        // 5. Claimed weight
        self.claimed_weight.serialize_compressed(&mut bytes).unwrap();

        // 6. Base tag tau
        self.base_tag.serialize_compressed(&mut bytes).unwrap();

        // 7. Audit tag rho (optional)
        if let Some(ref rho) = self.audit_tag {
            bytes.push(1);
            rho.serialize_compressed(&mut bytes).unwrap();
        } else {
            bytes.push(0);
        }

        // 8. Public Key PK
        self.public_key.serialize_compressed(&mut bytes).unwrap();

        bytes
    }

    /// Print packet header and cryptographic field inspection
    pub fn display_inspection(&self, label: &str) {
        println!("+-------------------------------------------------------------------------------+");
        println!("| [PACKET INSPECTION] {:<57} |", label);
        println!("+-------------------------------------------------------------------------------+");
        println!("| Source ID:    {:<63} |", String::from_utf8_lossy(&self.source_node_id));
        println!("| Source IP:    {:<63} |", self.source_ip);
        println!("| Round:        {:<63} |", self.round_r);
        println!("| Public Key:   {:<63} |", g2_to_hex(&self.public_key)[..48].to_string() + "...");
        println!("| Weight w^(i): {:<63} |", fr_to_hex(&self.claimed_weight)[..48].to_string() + "...");
        println!("| Base Tag tau: {:<63} |", g1_to_hex(&self.base_tag)[..48].to_string() + "...");
        let audit_str = match &self.audit_tag {
            Some(rho) => g1_to_hex(rho)[..48].to_string() + "...",
            None => "None (RTAA Base)".to_string(),
        };
        println!("| Audit Tag rho:{:<63} |", audit_str);
        println!("+-------------------------------------------------------------------------------+");
    }
}
