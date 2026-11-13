# RTAA+: Rotating Threshold Aggregate Authenticators with Non-Frameability

## 1. Project Overview

This repository contains the implementation of **Rotating Threshold Aggregate Authenticators (RTAA)** and its improved version, **RTAA+**, proposed to provide secure and accountable authentication for aggregated sensor and IoT reports.

The system is designed for scenarios where multiple parties or sensors periodically submit numeric reports to an **untrusted Aggregator**. Instead of individually processing every authentication value, the reports and their authentication information are aggregated so that the Aggregator can efficiently construct and verify a combined result.

The work first proposes **RTAA** and analyzes its correctness, consistency, binding properties, computational cost, and blame mechanism. During the security analysis, an **identity–weight relabeling vulnerability** was identified in the base RTAA construction.

To address this vulnerability, **RTAA+** was proposed as an improved version. RTAA+ introduces a non-aggregated per-party audit tag that binds each reporting identity to its submitted weight. This prevents an untrusted Aggregator from relabeling valid weights between identities and falsely blaming an honest party.

The implementation uses **BN254 elliptic-curve operations, pairings, threshold key generation, aggregate authentication, bisection-based blame, and the RTAA+ audit mechanism.**

---

## 2. Research Problem

In real-time sensor and IoT environments, many sensors continuously send periodic readings such as temperature, power consumption, pressure, or other measurements.

When the number of reporting sensors increases, individually processing, storing, and verifying every authentication value becomes computationally and communication-intensive. Aggregate authentication can reduce these costs by combining multiple reports into a single verifiable aggregate.

However, when the Aggregator is untrusted and is also responsible for identifying a faulty reporting party, an additional security problem arises: the Aggregator may manipulate the association between a party's identity and its submitted weight and falsely blame an honest party.

Therefore, the system needs both:

- Efficient aggregate authentication for multiple sensor reports.
- Protection against false blame or **framing of honest reporting parties**.

---

## 3. Proposed Approach

The project follows the progression:

**RTAA → Security Analysis → Identity–Weight Relabeling Attack → RTAA+**

### RTAA

The first proposed construction is **RTAA**, which combines:

- Threshold key generation
- Round-specific authentication
- Linear/homomorphic authentication
- Aggregate verification
- Bisection-based blame

RTAA allows multiple reporting parties to authenticate their reports and allows the Aggregator to construct and verify an aggregate.

### Security Analysis

During the security analysis of RTAA, the construction was examined under a threat model where the Aggregator is malicious.

The analysis identified that the aggregate consistency check preserves only the total weight. It does not independently guarantee that every weight remains associated with its original identity.

### Identity–Weight Relabeling Attack

The identified attack allows the Aggregator to exchange valid weights between two identities while preserving the aggregate sum:

\[
(w_A+w_B)\equiv(w_B+w_A)\pmod q.
\]

Therefore, the aggregate consistency check can still pass even though the identity–weight associations have been changed.

This can cause the blame procedure to incorrectly identify an honest party.

### RTAA+

To address this weakness, **RTAA+** was proposed.

RTAA+ adds a non-aggregated audit tag for every reporting party:

\[
\rho^{(i)}
=
H_3(GID\parallel r\parallel ID^{(i)}\parallel w^{(i)})^{sk^{(i)}}.
\]

The audit tag binds the reporting identity directly to its submitted weight.

The audit information is not included in the aggregate. Instead, it is checked during the enhanced blame procedure, **Judge+**, before performing the bisection process.

---

## 4. System Objective

The main objectives of the project are:

1. Efficient authentication of multiple reporting parties.
2. Secure aggregation of authenticated reports.
3. Verification of the aggregated result.
4. Identification of a faulty reporting party when verification fails.
5. Prevention of identity–weight relabeling attacks.
6. Protection of honest parties from false blame.
7. Evaluation of the computational performance of RTAA and RTAA+.

---

## 5. Main Cryptographic Components

The implementation uses the following cryptographic components:

- **BN254 elliptic curve**
- **Pairing operations**
- **SHA-256**
- **Pedersen-style commitments**
- **Threshold key generation**
- **Homomorphic/linear authentication**
- **Hash-to-group/field operations**
- **Bilinear pairing verification**

The implementation is written in **Rust** using the Arkworks ecosystem.

---

## 6. RTAA Construction

RTAA consists of the following major algorithms:

### Setup

The system initializes the cryptographic parameters, generators, group settings, and protocol configuration.

### ThreshKeyGen

A threshold committee jointly generates the round-specific authentication material.

Pedersen-style polynomial commitments are used during the distributed key-generation process.

The round-specific scalar is derived as:

\[
\alpha_r=H_1(\theta_r,r,GID).
\]

The corresponding power commitments are generated for aggregate verification.

### Auth

Each reporting party computes a weight from its submitted message:

\[
w^{(i)}
=
\sum_j m_j^{(i)}\alpha_r^{j+1}.
\]

The party then generates its authentication tag:

\[
\tau^{(i)}
=
\left(
H_0(GID\parallel r\parallel ID^{(i)})
g_1^{w^{(i)}}
\right)^{sk^{(i)}}.
\]

### Agg

The Aggregator combines the authentication tags, message components, and weights from multiple reporting parties.

### Verify

The Aggregator verifies:

- Reporting identities are distinct.
- The aggregate message and aggregate weight are consistent.
- The aggregated authentication passes the pairing-based verification.

### Judge

If aggregate verification fails, RTAA uses a recursive bisection-based blame procedure to identify a potentially faulty reporting party.

---

## 7. RTAA+ Construction

RTAA+ extends RTAA by adding a separate audit tag for each reporting party.

The audit tag is:

\[
\rho^{(i)}
=
H_3(GID\parallel r\parallel ID^{(i)}
\parallel w^{(i)})^{sk^{(i)}}.
\]

Unlike the main authentication tag, the audit tag is **not aggregated**.

It preserves the association between:

\[
ID^{(i)} \longleftrightarrow w^{(i)}.
\]

During **Judge+**, the audit tag is checked before the bisection-based blame procedure.

If the Aggregator has exchanged weights between identities, the corresponding audit verification fails and the relabeling can be detected.

---

## 8. Security Problem Addressed by RTAA+

The main security issue identified in RTAA is the **identity–weight relabeling attack**.

Suppose two parties \(A\) and \(B\) have weights:

\[
w_A,\quad w_B.
\]

A malicious Aggregator can exchange them:

\[
w_A' = w_B,
\qquad
w_B' = w_A.
\]

However,

\[
w_A'+w_B'
=
w_B+w_A
=
w_A+w_B.
\]

Therefore, the aggregate consistency relation can remain valid.

The problem is that the individual identity-to-weight association has been changed.

RTAA+ prevents this by including both the identity and weight inside the audit-tag hash:

\[
H_3(GID\parallel r\parallel ID^{(i)}\parallel w^{(i)}).
\]

Consequently, a swapped weight no longer matches the original party's audit tag.

---

## 9. Threat Model

The implementation considers an **untrusted or malicious Aggregator**.

The adversary may:

- Intercept messages.
- Modify packets.
- Exchange weights between reporting identities.
- Construct a manipulated aggregate.
- Execute the blame procedure on the manipulated aggregate.

The threat model also allows up to \(\ell-1\) malicious co-dealers and assumes that all reporting parties except the targeted honest party may be controlled by the adversary.

The honest target's long-term secret key remains unknown to the adversary.

The implementation specifically demonstrates the identity–weight relabeling attack without requiring the adversary to forge the target party's private-key-based authentication.

---

## 10. System Workflow

The overall workflow is:

**1. System Setup**

↓

**2. Threshold Key Generation**

↓

**3. Reporting Party Generates Message and Weight**

↓

**4. Authentication**

↓

**5. RTAA/RTAA+ Packet Transmission**

↓

**6. Aggregator Collects Reports**

↓

**7. Aggregate Construction**

↓

**8. Aggregate Verification**

↓

**9. If Verification Fails → Judge / Judge+**

↓

**10. Detect Faulty or Relabeled Identity**

---

## 11. System Architecture

The system consists of the following logical components:

### Reporting Parties

Each reporting party:

- Generates its secret/public key material.
- Creates a report.
- Computes its authentication weight.
- Generates the RTAA authentication tag.
- Generates the RTAA+ audit tag.

### Aggregator

The Aggregator:

- Receives authenticated reports.
- Constructs the aggregate.
- Performs aggregate verification.
- Runs Judge or Judge+ when verification fails.

The Aggregator is treated as **untrusted**.

### Threshold Committee

The threshold committee participates in generating the round-specific authentication scalar.

### Verification and Blame Layer

The verification layer checks the aggregate authentication.

If verification fails:

- RTAA uses the base bisection-based Judge.
- RTAA+ first checks the non-aggregated audit tags and then performs blame resolution.

---

## 12. Project Structure

```text
RTAA+/
├── .gitignore
├── README.md
├── generate_paper_figures.py
├── results/
│   ├── benchmark_interceptor.json
│   ├── fig1_table3_execution_cost.png
│   └── fig2_dispute_blame_latency.png
│
└── rtaa_rust_interceptor/
    ├── Cargo.toml
    ├── Cargo.lock
    ├── README.md
    └── src/
        ├── crypto.rs
        ├── interceptor.rs
        ├── main.rs
        ├── packet.rs
        └── protocol.rs
```

---

## 13. Module Description

### `crypto.rs`

Contains the cryptographic primitives used by RTAA and RTAA+, including BN254 operations, SHA-256 hashing, group operations, pairing-related functionality, and hash-to-group/field functions.

### `protocol.rs`

Implements the main RTAA and RTAA+ protocol algorithms, including setup, threshold key generation, authentication, aggregation, verification, Judge, and Judge+.

### `packet.rs`

Defines the network packet structure used to represent authenticated reports and provides packet serialization.

### `interceptor.rs`

Implements the simulated network interception environment and the identity–weight swapping attack.

### `main.rs`

Runs the complete demonstration, including setup, key generation, report generation, aggregation, verification, attack execution, blame resolution, and benchmarking.

---

## 14. Cryptographic Hash Functions

The implementation uses four protocol-specific hash functions.

### \(H_0\)

Binds the group identifier, round number, and reporting identity to the authentication tag.

### \(H_1\)

Derives the round-specific scalar from the threshold-generated value.

### \(H_2\)

Used during party registration and public-key proof-of-possession.

### \(H_3\)

Used by RTAA+ to bind the reporting identity and weight to the non-aggregated audit tag.

The implementation maps inputs into the required BN254 group or field representations used by the protocol.

---

## 15. Threshold Key Generation

RTAA uses threshold key generation so that the round-specific authentication material is not controlled by a single party.

The implementation uses polynomial-based threshold generation with Pedersen-style commitments.

For a threshold \(t\), the committee members generate polynomial shares and corresponding commitments.

The resulting threshold-generated value is used to derive:

\[
\alpha_r=H_1(\theta_r,r,GID).
\]

The implementation also constructs the required power commitments:

\[
\Gamma_j=g_1^{\alpha_r^j}.
\]

These commitments are later used during aggregate verification.

---

## 16. Authentication and Aggregation

For every reporting party \(i\), the submitted report is converted into a protocol weight:

\[
w^{(i)}
=
\sum_jm_j^{(i)}\alpha_r^{j+1}.
\]

The RTAA authentication tag is then computed using the party's secret key:

\[
\tau^{(i)}
=
\left(
H_0(GID\parallel r\parallel ID^{(i)})
g_1^{w^{(i)}}
\right)^{sk^{(i)}}.
\]

The Aggregator combines the authentication tags and report values.

The aggregate weight is:

\[
w_{\mathrm{agg}}
=
\sum_iw^{(i)}.
\]

The aggregate message is similarly formed from the submitted message components.

---

## 17. Aggregate Verification

The verification procedure checks the validity of the aggregate.

The implementation verifies:

1. Reporting identities are distinct.
2. The aggregated message corresponds to the aggregated weight.
3. The aggregate authentication satisfies the pairing-based verification relation.

The aggregate weight is independently reconstructed from the aggregated message and the public power commitments.

This ensures that the aggregate is internally consistent before the authentication check is accepted.

---

## 18. Identity–Weight Relabeling Attack

The repository implements the attack identified during the security analysis of RTAA.

Two authenticated packets are selected.

Their claimed weights are exchanged:

\[
w_A \leftrightarrow w_B.
\]

The total aggregate weight remains unchanged:

\[
w_A+w_B=w_B+w_A.
\]

Therefore, the aggregate consistency relation can still hold.

However, the authentication relation associated with an individual identity can fail because the weight no longer belongs to the identity that originally generated the authentication information.

This demonstrates that the base RTAA construction does not provide sufficient identity–weight binding for non-frameable blame adjudication.

---

## 19. RTAA+ Audit Mechanism

RTAA+ adds an audit tag for every reporting party:

\[
\rho^{(i)}
=
H_3(GID\parallel r\parallel ID^{(i)}
\parallel w^{(i)})^{sk^{(i)}}.
\]

The tag is kept separate from the aggregate.

During Judge+, each party's audit information can be checked against its claimed identity and weight.

If the Aggregator has swapped the weights of two parties, the audit verification fails.

This allows RTAA+ to detect the identity–weight relabeling before relying on the base bisection procedure.

---

## 20. Judge and Judge+

### Base Judge

The base RTAA Judge uses recursive bisection.

It repeatedly constructs subaggregates and performs pairing-based verification until the problematic reporting party is identified.

The worst-case pairing complexity is:

\[
O(\mu\log\mu).
\]

### Judge+

RTAA+ first checks the non-aggregated audit tags.

If an audit tag fails, the corresponding identity can be identified directly.

If no audit failure is detected, the implementation falls back to the base bisection procedure.

The audit-tag verification itself is constant-size, while the current implementation checks the reporting parties sequentially.

---

## 21. Implementation Challenges

### 1. Hash-to-Curve Implementation

Implementing the four hash functions \(H_0\), \(H_1\), \(H_2\), and \(H_3\) correctly was challenging because they must map inputs to the required BN254 points or field elements while maintaining the necessary subgroup properties.

### 2. Theorem 1 Relabeling Attack

Implementing the identity–weight relabeling attack required exchanging the weights of two parties while preserving the aggregate consistency check, i.e.,

\[
(w_A+w_B)\equiv(w_B+w_A)\pmod q,
\]

while causing the identity-dependent authentication check to fail.

### 3. Accurate Benchmarking

Measuring the performance of the pairing-heavy operations required separate benchmark loops for \(\mathsf{Auth}\), \(\mathsf{Agg}\), \(\mathsf{Verify}\), and \(\mathsf{Judge}\) to obtain accurate execution times.

---

## 22. Experimental Evaluation

The implementation evaluates the execution cost of the major RTAA and RTAA+ operations for different reporting subset sizes.

The experiments consider three representative scales:

- **Small scale:** \(\mu=16\)
- **Medium scale:** \(\mu=64\)
- **Large scale:** \(\mu=128\)

The evaluated operations include:

- Setup
- ThreshKeyGen
- Auth
- Agg
- Verify
- Base Judge
- Judge+ (RTAA+)

The execution latency is presented on a logarithmic scale because the cryptographic operations have significantly different execution times.

---

## 23. Benchmark Results

The updated benchmark results show that **Verify and the base Judge dominate the execution cost** as the reporting subset size increases, while the RTAA+ Judge+ operation remains substantially lower in the evaluated experiments.

The execution-cost results are approximately:

| Operation | \(\mu=16\) | \(\mu=64\) | \(\mu=128\) |
|---|---:|---:|---:|
| Setup | ~20 ms | ~80 ms | ~160 ms |
| ThreshKeyGen | ~4 ms | ~9 ms | ~15 ms |
| Auth | ~0.8 ms | ~0.8 ms | ~0.8 ms |
| Agg | ~0.06 ms | ~0.3 ms | ~0.4 ms |
| Verify | ~100 ms | ~300 ms | ~550 ms |
| Judge (Base) | ~100 ms | ~300 ms | ~500–600 ms |
| Judge+ (RTAA+) | ~8 ms | ~9 ms | ~5 ms |

The results indicate that the pairing-heavy verification and base blame operations become increasingly expensive with larger reporting subsets, whereas RTAA+ provides substantially lower blame-resolution latency.

---

## 24. RTAA+ Blame-Resolution Results

The updated blame-resolution experiment directly compares the base RTAA Judge with the RTAA+ Judge+.

The results demonstrate substantial performance improvement for RTAA+.

At:

\[
\mu=16,
\]

the measured improvement is approximately:

\[
\boxed{12.3\times\text{ speedup}}.
\]

At:

\[
\mu=128,
\]

the measured improvement reaches approximately:

\[
\boxed{103.0\times\text{ speedup}}.
\]

The base RTAA Judge increases significantly as the reporting subset size grows because it repeatedly performs aggregate verification during the bisection process.

RTAA+ instead uses the non-aggregated audit tag to detect an invalid identity–weight association directly, resulting in substantially lower blame-resolution latency in the evaluated implementation.

These results demonstrate the practical performance benefit of the RTAA+ repair for larger reporting subsets.

---

## 25. Conclusion

RTAA is a threshold-generated aggregate authenticator with a bisection-based blame algorithm. Our analysis shows that correctness alone doesn’t guarantee non-frameability when the same untrusted aggregator both builds the disputed aggregate and runs the blame procedure. The attack works because Verify’s well-formedness and consistency checks only look at sums over the reporting set. The authentication check that Judge rules on is the only place an individual identity gets tied to an individual weight, and that tie is asserted by the aggregator, not confirmed by the party itself.

RTAA+ closes the gap with one extra non-aggregated tag per party. It costs at most \(\mu\) additional pairings, and only when Judge has to run anyway.

Several things remain for future work: a full explicit reduction for Theorem 2 with a stated security loss, the complete EUF-CMIA-style unforgeability game and reduction for the base authentication check in Equation (7), and a broader comparison against recent accountable threshold aggregate signature schemes under larger, more realistic deployment parameters.
