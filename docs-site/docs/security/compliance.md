---
title: Compliance Overview
description: Audit infrastructure for EU AI Act, NIST AI RMF, SOC 2, and ISO 42001. Agent actions write immutable records to kavach_audit_logs with identity, resource, and action.
---

# Compliance Overview

TheAuth is built with compliance requirements in mind. Every agent action produces an immutable audit record with enough detail to satisfy the logging and oversight obligations of major AI governance frameworks.

!!! note
    The EU AI Act high-risk provisions take effect August 2, 2026. TheAuth gives you the audit infrastructure to meet the Article 12 and Article 14 requirements before that deadline.

## What TheAuth provides

| Requirement | TheAuth feature |
|---|---|
| Immutable audit log | `kavach_audit_logs` table with result, reason, duration, IP, user-agent |
| Human oversight | Approval flows (CIBA), delegation depth limits, permission constraints |
| Access control | Resource+action permission model with constraints (IP, time window, rate) |
| Identity traceability | Every action links `agentId`, `userId`, resource, action, parameters |
| Export | `kavach.audit.export()` as JSON or CSV |
| Anomaly detection | High-frequency, high-denial-rate, off-hours, privilege escalation |

## EU AI Act (August 2, 2026 enforcement)

The EU AI Act imposes obligations on providers and deployers of high-risk AI systems.

**Article 9 - Risk management system**

TheAuth supports Article 9 through:

- Permission constraints (`maxCallsPerHour`, `timeWindow`, `ipAllowlist`) that enforce operational boundaries
- Anomaly detection that flags unusual patterns before they become incidents
- Trust scoring that adjusts agent autonomy based on track record

**Article 12 - Record-keeping**

The `kavach_audit_logs` table is append-only. Entries record agent ID, user ID, action, resource, outcome, duration, and timestamp. Export via `kavach.audit.export({ format: 'csv' })` to produce records for regulators.

**Article 14 - Human oversight**

The `requireApproval` constraint on any permission triggers a CIBA-style approval flow. No action proceeds until a human approves it. Delegation depth limits (`maxDepth`) prevent unbounded autonomous chains.

## NIST AI RMF

| Function | Subcategory | TheAuth feature |
|---|---|---|
| GOVERN | GV-1.1 | Policy engine with per-permission constraints |
| MAP | MP-2.1 | Agent type classification (`autonomous`, `delegated`, `service`) |
| MEASURE | ME-1.1 | Trust scoring from audit log |
| MANAGE | MG-2.2 | Token rotation, revocation, delegation expiry |

## SOC 2 Type II

Relevant trust service criteria:

| Criteria | TheAuth feature |
|---|---|
| CC6.1 (Logical access) | Bearer tokens with SHA-256 hash storage, no plaintext recovery |
| CC6.3 (Access removal) | Revocation is immediate and permanent |
| CC7.2 (Anomalies monitored) | Anomaly detection on high-frequency and high-denial-rate patterns |
| CC9.2 (Risk monitoring) | Trust scoring per agent |

## ISO 42001

ISO 42001 (AI Management System) requires documented controls for AI system operation. TheAuth's audit trail satisfies the logging control requirements. The permission engine with constraints satisfies the access control requirements.

## Related pages

- [Audit Events](../reference/audit-events.md)
- [GDPR](gdpr.md)
- [SOC 2 and ISO 42001](soc2-iso42001.md)
- [Permission Engine](../guides/permissions.md)
