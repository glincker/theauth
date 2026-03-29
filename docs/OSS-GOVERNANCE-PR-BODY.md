# OSS Governance Infrastructure & Community Enhancement (Round 2)

## Summary

This PR implements comprehensive GitHub community infrastructure and operational playbooks to accelerate contributor onboarding, clarify maintainer workflows, and provide transparent community governance. Expands upon [Launch Round 1] with label taxonomy, triage automation, Discussions setup, and release versioning strategy.

## Changes at a Glance

### New Files (7)

✨ **Community infrastructure:**

- `.github/labels.yml` — 24-label seed file with colors/descriptions for consistent triage
- `.github/ISSUE_TEMPLATE/config.yml` — Route blank issues to Discussions/Discord/security email
- `.github/FUNDING.yml` — GitHub Sponsors + OpenCollective funding links
- `.github/pull_request_template.md` — Enhanced to require release-impact & changeset declaration

🏗️ **Maintainer playbooks:**

- `docs/maintainer-triage-playbook.md` — Daily/weekly triage workflow, SLA enforcement (2 biz days), closure policy
- `docs/triage-label-taxonomy.md` — 24-label system (7 type + 4 priority + 8 area + 6 state + 2 good-first + 3 meta)
- `docs/discussions-playbook.md` — GitHub Discussions setup, automation, category templates, escalation paths

📋 **Operational templates:**

- `docs/oss-community-pr-summary.md` — Ready-to-use PR writeup for governance changes (this template)

### Updated Files (8)

📖 **Policy & governance docs (created in Round 1, now cross-linked):**

- `GOVERNANCE.md` — Roles (maintainers/contributors), decision process, contribution pathway
- `SUPPORT.md` — Support channels (Discussions, Discord, email), intake checklist, SLAs
- `MAINTAINERS.md` — Responsibilities, merge policy, release lanes, incident handling
- `CODE_OF_CONDUCT.md` — Community expectations (pre-existing)
- `SECURITY.md` — Security policy (pre-existing)

🔗 **Cross-links & integration:**

- `README.md` — Added "Community and support" hub section linking all governance docs
- `CONTRIBUTING.md` — Enhanced with monorepo workflow, changeset guidance, support links (Round 1)
- `LAUNCH-CHECKLIST.md` — Marked 10/10 items complete, documented Wave A/B versioning strategy (Round 1)

🔧 **Release coordination:**

- `.changeset/launch-0-1-0.md` — Wave A: 10 packages → 0.1.0 (core + clients)
- `.changeset/launch-adapters-and-plugins-1-0-0.md` — Wave B: 15 packages → 1.0.0 (adapters/plugins)
- `.changeset/config.json` — Disabled fixed groups; added experimental peer-dependent (Round 1)

## Why This Matters

### For Contributors

- **Clear entry points:** Good-first-issue label + CONTRIBUTING guide reduces friction for new contributors
- **Transparent process:** GOVERNANCE.md shows how decisions are made; pathway to maintainer status is explicit
- **Responsive support:** 2-business-day SLA on GitHub Discussions + monitored Discord channel
- **Self-serve resources:** Triage playbook shows how we categorize/prioritize; no mystery about what "P2" means

### For Maintainers

- **Sustainable triage:** Label taxonomy + daily playbook prevents label sprawl and decision fatigue
- **Automated escalation:** Discussions playbook routes security/urgent issues appropriately (not lost in Q&A)
- **Release confidence:** Wave A/B changesets document intention to separate pre-1.0 adapters from stable core
- **Operational clarity:** Playbooks written down means knowledge isn't in one person's head

### For KavachOS as a Project

- **Community trust:** Transparent SLAs, roles, and process increase contributor confidence
- **Governance maturity:** Distinguishes from abandoned projects; shows long-term commitment
- **Reduced support burden:** Discussions + FAQ pinning offload repetitive questions from Issues
- **Sustainable growth:** Label taxonomy and triage playbook allow velocity to scale without chaos

## Release Impact

**Release type:** `minor` (adds governance infrastructure, updates community docs)

**Changeset required:** Yes — updates CONTRIBUTING.md, adds playbooks, community docs (use existing `.changeset/` entries from LAUNCH checklist)

## Files Changed: By Category

### GitHub Community Infrastructure

```
.github/
  ├── labels.yml (new) — 24-label seed file
  ├── ISSUE_TEMPLATE/
  │   └── config.yml (new) — Discussion/Discord routing
  ├── FUNDING.yml (new) — Sponsors config
  └── pull_request_template.md (updated) — Release-impact + changeset checks
```

### Maintainer Playbooks & Governance

```
docs/
  ├── maintainer-triage-playbook.md (new) — Daily/weekly triage SLAs
  ├── triage-label-taxonomy.md (new) — 24-label definitions & process
  ├── discussions-playbook.md (new) — Setup, categories, escalation
  └── oss-community-pr-summary.md (new) — Template for this PR

/root
  ├── MAINTAINERS.md (updated) — Links to playbooks, label config
  ├── GOVERNANCE.md (updated) — References  triage label use
  ├── CONTRIBUTING.md (updated) — References changesets + support
  ├── SUPPORT.md (updated) — References Discussions + SLAs
  └── README.md (updated) — Added "Community" section hub

.changeset/
  ├── launch-0-1-0.md (existing) — Wave A 0.1.0
  └── launch-adapters-and-plugins-1-0-0.md (existing) — Wave B 1.0.0
```

## Validation Checklist

- [x] All new governance docs link to each other (no orphans)
- [x] MAINTAINERS.md references all playbook paths
- [x] Labels match triage-label-taxonomy.md + colors distinct per category
- [x] Discussions categories align with support channels (SUPPORT.md)
- [x] Triage playbook SLAs match SUPPORT.md response times (2 biz days)
- [x] PR template matches governance requirements (release-impact, changeset)
- [x] README.md hub links all policy docs in one place
- [x] CONTRIBUTING.md references monorepo workflow + changesets
- [x] No hardcoded @names (using "maintainer" / "area-expert" roles)
- [x] Playbooks assume Wave A/B release strategy (documented in GOVERNANCE.md)

## Risk & Rollback

**Risk level:** Low — documentation-only, no behavior changes

**Rollback:** Delete `.github/labels.yml`, revert MAINTAINERS.md link updates, restore old PR template. Discussions can be disabled in repo settings if needed.

**Testing:**

- Validate labels.yml YAML syntax: ✓
- Confirm all playbook cross-links resolve: ✓
- Verify SUPPORT.md SLAs align with triage playbook: ✓
- Check README.md hub links to all docs: ✓

## Deployment

**No deployment required.** These are documentation & configuration files.

**Next steps after merge:**

1. Apply labels via GitHub: `for label in labels.yml: gh label create` (will provide script)
2. Enable GitHub Discussions in repo settings (not auto-enabled)
3. Create pinned announcements per `docs/discussions-playbook.md` → Announcements category
4. Link Discord/Discussions in GitHub profile or pin issue

## Following Work (Optional)

- [ ] Create GitHub Actions automation to sync `.github/labels.yml` on each commit
- [ ] Build discussion templates for each category (auto-populated category descriptions)
- [ ] Add bot comments to high-traffic discussions (auto-answer rate-limited questions)
- [ ] Establish label audit schedule (quarterly review for stale/unused labels)

## Questions?

See [GOVERNANCE.md](./GOVERNANCE.md) for decision process or ping maintainers in Discussions.

---

## Metrics (Optional, for maintainer review)

- **Governance maturity:** Moved from implicit to explicit (roles, process, SLAs documented)
- **Contributor activation energy:** Cut from "read entire codebase to understand workflow" to "read CONTRIBUTING.md + label definitions"
- **SLA enforcement capability:** Labeled issues can now auto-age if unanswered (measurable via label queries)
- **Triage velocity:** Pre-defined categories & playbook time-box = less context-switching

## Related Issues & PRs

- Fixes contributor friction: #TODO (reference GitHub issue if exists)
- Builds on launch checklist: See `LAUNCH-CHECKLIST.md`
- Release strategy: See `docs-local/release-versioning-runbook-2026-03-29.md`
