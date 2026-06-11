# Framework mapping primer

Your capstone must declare and defend a primary compliance framework. Pick one. Map every policy to at least one control from it. The OSCAL component cites that framework's catalog.

The three options below are all defensible for this workload. None is "right." Your write-up explains why your choice fits Acme's situation.

## HIPAA Security Rule

The most direct fit, because the workload handles PHI. Relevant Administrative, Physical, and Technical Safeguards, with the citations you'll use most:

| Control | What it requires |
|---|---|
| **164.308(a)(1)** | Security Management Process — risk analysis, sanction policy, info system activity review. |
| **164.308(a)(7)** | Contingency Plan — data backup, disaster recovery. Versioning on PHI buckets. |
| **164.312(a)(1)** | Access Control — unique user IDs, automatic logoff, encryption at rest. |
| **164.312(a)(2)(iv)** | Encryption and decryption — addressable but effectively required. |
| **164.312(b)** | Audit Controls — record and examine activity in systems with PHI. |
| **164.312(d)** | Person or Entity Authentication. |
| **164.312(e)(1)** | Transmission Security — encryption + integrity in transit. |

OSCAL note: there isn't an official NIST OSCAL catalog for HIPAA itself. Most teams cite **NIST SP 800-66 Rev. 2** (Implementing the HIPAA Security Rule) as the catalog and reference 164.x sections as `props` on each `implemented-requirement`.

## SOC 2 Trust Services Criteria

The right pick if Acme's near-term motivation is enterprise customer trust. Common criteria you'll touch:

| Control | What it requires |
|---|---|
| **CC6.1** | Logical access controls — restrict access to information assets. |
| **CC6.3** | Authorization — least privilege, periodic access reviews. |
| **CC6.6** | Boundary protection — protect from unauthorized access to internal information. |
| **CC6.7** | Transmission security — protect data in transit. |
| **CC7.2** | System monitoring — detection of anomalies, security events. |
| **A1.2** | System availability — backup, recovery. |

OSCAL note: AICPA does not publish an official OSCAL TSC catalog. Teams frequently use a community-maintained one or map TSC to NIST 800-53 and cite the latter.

## CMMC Level 2

The right pick if Acme is pursuing federal pilots. CMMC L2 inherits 110 NIST 800-171 controls. The most relevant for this workload:

| Practice | What it requires |
|---|---|
| **AC.L2-3.1.1** | Authorized access enforcement. |
| **AC.L2-3.1.3** | Information flow control. |
| **AC.L2-3.1.5** | Least privilege. |
| **AU.L2-3.3.1** | Generate audit records. |
| **SC.L2-3.13.1** | Boundary protection. |
| **SC.L2-3.13.8** | Encryption in transit. |
| **SC.L2-3.13.11** | FIPS-validated cryptography for protecting CUI confidentiality. |
| **SI.L2-3.14.6** | System monitoring — detection of attacks. |

OSCAL note: NIST publishes 800-171 Rev. 3 in OSCAL. CMMC's catalog is a profile over 800-171.

## What this looks like in practice

Pick one framework. In every Rego policy's metadata block, put a `controls` field listing the relevant control IDs:

```rego
# METADATA
# title: SC-28 — Encryption at rest for PHI buckets
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#     - "164.308(a)(7)"
#   severity: high
package compliance.hipaa.encryption
```

In OSCAL, every `implemented-requirement` lives under a `control-implementation` whose `source` is the URI of your chosen catalog. The grader follows the chain: starter → policy → OSCAL → catalog. If the chain breaks, the layer fails.

## Multi-framework submissions

You may map secondary frameworks in the OSCAL `props` and in your write-up. You may not write a Rego policy whose primary control is from a framework you didn't declare. Pick a primary, defend it, then cross-reference where helpful.
