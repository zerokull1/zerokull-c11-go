# ZEROMANI (`zerokull1`) — Cryptographic Proof of Authorship & Priority Registry

- **Author:** `zerokull1` (`0x5A45524F4D414E49ULL` / `0x5A45524F4B554C4CULL`)
- **Timestamp:** `2026-11-21 13:05:42 UTC`
- **Public Identity & Sponsorship Anchor (TON):** `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z` ([Tonviewer](https://tonviewer.com))
- **Registry Document License:** GNU Affero General Public License v3.0 (AGPL-3.0)
- **Proprietary Binary Modules (`raw_opcode_release`):** All Rights Reserved. Closed-source bare-metal machine code; no license is granted to decompile, distribute, or use outside authorized hardware envelopes.

---

## Purpose & Verification Notice

This repository acts as a cryptographic timestamp notary. It contains **only SHA-256 digests** of the closed-source bare-metal modules (`raw_opcode_release`), proving prior art and exact authorship without disclosing proprietary machine code.

### Independent Verification Anchors
1. **GitHub Funding Anchor:** The TON address listed above matches `.github/FUNDING.yml` in `zerokull1/zero-timing-core`.
2. **Cryptographic Signature:** Verify detached GPG/SSH signature (`PROOF_OF_AUTHORSHIP.md.asc` / `.sig`) against the author's registered GitHub signing key.
3. **Blockchain Timestamp:** Verify `PROOF_OF_AUTHORSHIP.md.ots` via [OpenTimestamps](https://opentimestamps.org) (`ots verify PROOF_OF_AUTHORSHIP.md.ots`).

---

## 1. Full Closed-Contour Monolith Digest

| Artifact | SHA-256 Digest |
| :--- | :--- |
| `raw_opcode_release` (Archive) | `c8879a0a5ebf1c8ee2cdcf1fad6a55f1937e64a85c6ab98ad3273a05dd7d2f2d` |

---

## 2. Individual Bare-Metal Module Digests (SHA-256)

| Module | Size (Bytes) | SHA-256 Digest |
| :--- | ---: | :--- |
| `bot_capsule.bin` | 217 | `90bd68a3f7049cb15445a3da996a951f7d52893421007f679029d306bc860d6f` |
| `cryo_zeroize_cap.bin` | 172 | `feb7bcb8f8e7c7c663497e087c257d1d3ab3df888ea68259e367779611e516f6` |
| `drift_capsule.bin` | 375 | `a0172204d221844a04e2778a2eadc88189f5b78e6b1657bcab1f89261088a4bf` |
| `evo_capsule.bin` | 117 | `742a74e5c66ec09f4b191f5056295ca445a88b92481190702eafaceb1fa0256f` |
| `flow_2way_cap23.bin` | 458 | `cf406012052b6eb61de6128e845206d58cae87bbf956dca9e8c75a50194f24d4` |
| `flow_capsule.bin` | 156 | `f65e95d811024d08833ec47e111dd7d5ebc063f962b98eb860268f6638e0d400` |
| `full_policy_mcode.bin` | 28 | `24f2c8da37c8229f741ea44a81f526b7393ce62be94ffa40a4ae2919ed783850` |
| `hash5_capsule.bin` | 67 | `b153ffb949fcb14b464363fccfb2088e93504fd3d5ab27c3e00f2c18c767d985` |
| `hft_capsule.bin` | 45 | `d1bb22ae9df8c37a72700b76455ab2576c0f1acaba97e0fbac77bf2c6f22211e` |
| `ipv6_capsule.bin` | 211 | `a4c45781cfac3748240551eb82cba88a9be549fc02d2a8b8fd2e4de4a8813274` |
| `ja4_bot_capsule.bin` | 259 | `3a85dade05b4a21339a7cffaa9bef7cd3ae4d5908f0b6c63682a41926c64e7df` |
| `jitter_capsule.bin` | 105 | `c9c07b305919c07edf1d64baf241b3337846ca2040f416f5fa6eff30470e3941` |
| `millicode_vm.bin` | 314 | `deb8cc50fe6ea953169ab4eec179b5ef6d9f0c051a86965f97d2a7d5bd681b0a` |
| `millicode_vm_v2.bin` | 464 | `33be66eb9c62b4c9ccbb46ae482b42573ccdcfc5d42ef144302fda6f815d9f29` |
| `millicode_vm_v3.bin` | 561 | `414547df867b0c899dd6a633196aff153d745c1566d4138b6e810799a176eb98` |
| `nic_capsule.bin` | 589 | `ecd316ec18f0906cf80a265707ad40c9714d245cdeb1a1a0ecc4b700262ebde1` |
| `omni_mcode.bin` | 58 | `6baeadec171b7ae5f0c23df32d6ab0e904a735aa7a36ec8a573ed75f0627ddc5` |
| `omni_mcode_v3.bin` | 64 | `d8202d295ce053d754cf77dde9513bba248dede939d03d5747521d219d9e45c4` |
| `policy_mcode.bin` | 12 | `2b42b27598444ca4cfd1ca1f22ec420ac5d742c482f349ea91784acc50c7ed57` |
| `proto9_capsule.bin` | 236 | `cb12163a37b0403621dd4b08f326908c2e8ac7f513d608720f5e146380b43ff4` |
| `pulse_trap_capsule.bin` | 98 | `9b25bb885cf8e4f87f155a3231d76aa2473f4adb1d3e09a1a9b1d6d526273eed` |
| `ring1_capsule.bin` | 606 | `674313d9c6c67e363330cb8a4c4c20a378661dca81c1ea0d8f2b145470c17e00` |
| `ring1_cloak_gate.bin` | 666 | `d6a71e043abc93af3e36c0b6efbefad042663401371e00322e80b25977b74f29` |
| `rmm_soho_capsule.bin` | 102 | `90c14ba5a06268543ff75c4e3838b987f697969cb2d2e3729bb6881826b1775e` |
| `rx_capsule.bin` | 304 | `b24543bf6d29e162c800f84d5154e01da70d8cf03371d650ae9306745d3a82a2` |
| `simd_capsule.bin` | 45 | `cdb7b90fc0c71007af1897479d10f9bca891d9381a82ff31900d37c2bff4b73c` |
| `swarm_capsule.bin` | 211 | `0799dc5dca3bed392f18a9bd4c86dea0c8098345c114c1224bd285d8240d97d3` |
| `szi_capsule.bin` | 298 | `5386444558e7bbb112a2daf5fce7aa1cb5290492b6358e55014bd1c6af3f2e54` |
| `tarpit_capsule.bin` | 214 | `38e78161eda2248a5c884181e007dcfd153dc7ab8a5331e6dd09dc126dcd23c7` |
| `ttl_ct_capsule.bin` | 69 | `e4c2b0d546ae914643666d91fef1be524c411697926d214804dc2d9371a45087` |
| `vault_capsule.bin` | 190 | `48a48498e0dd54e90ff7c74b0cf98c19a5611239f81d3ec6525667f79c7f9b86` |
| `wave5_capsule.bin` | 467 | `f3ab16b801826c6d6ff1b9b9007cc58816657d3141f51e9ad89e567253dbe98e` |
| `zeromani_18caps.bin` | 4102 | `44877b6bf47ca29f015a7dcf930680fd7b17c0ebf0aabba89caeb6654c495e54` |
| `zeromani_20caps.bin` | 4491 | `c1387dbbc8eab310afd673dddc8b62e749b62f52722e4880a4a135dceac9b8f8` |
| `zeromani_21caps.bin` | 4974 | `cb7ed9f4aab17af8c8e06381898d83e48f2022f1e8845a07eb0da05c675096c9` |
| `zeromani_22caps.bin` | 5365 | `699df8adee8bc4001aec128596f9b0080f79d6f67d2920237cb60093047cd188` |
