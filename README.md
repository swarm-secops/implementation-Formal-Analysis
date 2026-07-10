# Verifpal Verification Models

This directory contains the modular Verifpal models used to support the security analysis of the proposed UAV swarm command-origin authentication protocol. The models are analyzed under an active Dolev-Yao adversary, where runtime wireless messages are attacker-mutable. Guarded values are used only for authenticated setup material or enrolled state.

## Individual Models

| No. | Model file                                   | Purpose                                                               | Verified query                                                                    | Screenshot                                              |
| --- | -------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------- |
| 01  | `models/01_minimal_runtime_authorization.vp` | Minimal MHT/FORS runtime authorization model                          | `authentication? Leader -> Follower: p_token` with acceptance precondition        | `screenshots/01_minimal_runtime_authorization_pass.png` |
| 02  | `models/02_runtime_ad_binding.vp`            | Runtime authorization with explicit (AD_q=(ID_L,q,M,R)) binding       | `authentication? Leader -> Follower: p_token` with acceptance precondition        | `screenshots/02_runtime_ad_binding_pass.png`            |
| 03  | `models/03_runtime_digest_binding.vp`        | Runtime authorization with (AD_q), (N_q), and (X_q) included in (d_q) | `authentication? Leader -> Follower: p_token` with acceptance precondition        | `screenshots/03_runtime_digest_binding_pass.png`        |
| 04  | `models/04_aead_confidentiality.vp`          | AEAD confidentiality of (K_E) and (cmd_q)                             | `confidentiality? ke`, `confidentiality? cmd_q`                                   | `screenshots/04_aead_confidentiality_pass.png`          |
| 05  | `models/05_enrollment_authentication.vp`     | GCS-authenticated enrollment of the command root (C_L)                | `authentication? GCS -> Follower: c_root` with enrollment precondition            | `screenshots/05_enrollment_authentication_pass.png`     |
| 06  | `models/06_keywrap_confidentiality.vp`       | Follower-specific wrapping confidentiality of (K_E) under (s_i)       | `confidentiality? si`, `confidentiality? ke`                                      | `screenshots/06_keywrap_confidentiality_pass.png`       |
| 07  | `models/07_role_binding.vp`                  | Mission-role binding of (ID_L), (ID_i), (M), and (C_L)                | `authentication? GCS -> Follower: c_root` with role-bound enrollment precondition | `screenshots/07_role_binding_pass.png`                  |

## How to Run

Each model can be verified independently:

```bash
verifpal verify models/01_minimal_runtime_authorization.vp
verifpal verify models/02_runtime_ad_binding.vp
verifpal verify models/03_runtime_digest_binding.vp
verifpal verify models/04_aead_confidentiality.vp
verifpal verify models/05_enrollment_authentication.vp
verifpal verify models/06_keywrap_confidentiality.vp
verifpal verify models/07_role_binding.vp
```

The corresponding verification outputs are stored in the `logs/` directory, and screenshots of the passing results are stored in the `screenshots/` directory.

## Notes on Modeling

The models are modular rather than monolithic. This avoids unnecessary symbolic state expansion while still covering the main protocol properties: runtime command authorization, digest binding, AEAD confidentiality, GCS-authenticated enrollment, follower-specific key wrapping, and mission-role binding.

Replay protection based on (1\le q\le N) and (q>q_L^{last}) is not encoded as a Verifpal query because it requires a stateful numerical comparison. This check is enforced by the follower-side acceptance rule in the protocol.
