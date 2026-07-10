# Verifpal Models for UAV Swarm Command-Origin Authentication

This repository contains the Verifpal models and verification logs used to support the security analysis of the proposed UAV swarm command-origin authentication protocol. The models are written for symbolic verification under an active Dolev-Yao adversary, where the attacker can inject, modify, replay, and delay messages, but cannot break the idealized cryptographic primitives.

The protocol combines GCS-authenticated enrollment, Merkle-root based command-token authorization, FORS-like one-time command openings, AEAD-protected command delivery, follower-specific key wrapping, and mission-role binding. Instead of placing all components in one monolithic Verifpal model, the verification is performed modularly. This avoids unnecessary symbolic state expansion and isolates the main security properties of the protocol.

## Model Summary

| File                              | Verified property                                                                                                     | Result |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------ |
| `01_runtime_ad_auth.vp`           | Runtime command-token authorization with explicit (AD_q=(ID_L,q,M,R)) binding                                         | PASS   |
| `02_runtime_digest_binding.vp`    | Runtime command-token authorization with (AD_q), (N_q), and (X_q) included in the verified digest (d_q)               | PASS   |
| `03_aead_confidentiality.vp`      | Confidentiality of the mission encryption key (K_E) and command plaintext (cmd_q) under the symbolic AEAD abstraction | PASS   |
| `04_enrollment_authentication.vp` | GCS-authenticated enrollment of the command root (C_L)                                                                | PASS   |
| `05_keywrap_confidentiality.vp`   | Confidentiality of (K_E) under the follower-specific wrapping secret (s_i)                                            | PASS   |
| `06_role_binding.vp`              | Mission-role binding of (ID_L), (ID_i), (M), and (C_L) through the GCS-authenticated mission state                    | PASS   |

## Modeling Notes

The runtime wireless fields are intentionally left attacker-mutable. This includes the command token, command index, ciphertext, and FORS-like opening. Guarded values are used only for authenticated pre-existing trust anchors or already enrolled state, such as the GCS public key or the command-root commitment accepted during enrollment.

The Merkle membership relation is modeled using a checked assertion, and the FORS-like opening is modeled using Verifpal's checked signature verification primitive. These are symbolic abstractions because Verifpal does not provide user-defined Merkle-tree or FORS primitives.

The runtime authentication query is conditioned on an accepted-command marker. This is necessary because Verifpal treats preprocessing of attacker-supplied candidate values as primitive usage, even when later checked verification rejects the execution. The precondition therefore captures the intended security claim: if a follower reaches the accepted-command state, then the command token used in the accepted verification path originates from the authorized leader-token holder.

Replay protection based on (1\le q\le N) and (q>q_L^{last}) is not encoded as a Verifpal query because it requires a stateful numerical comparison. In the protocol, this property is enforced by the follower-side monotonic counter update after successful command verification.

## Verification Environment

The models were checked using Verifpal under an active attacker setting. Each verification log in the `verification-logs/` directory contains the corresponding PASS output. Screenshots are also provided in the `screenshots/` directory for quick inspection.
