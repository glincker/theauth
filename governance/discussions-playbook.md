# GitHub Discussions Playbook

This guide helps maintainers set up and manage GitHub Discussions as the primary community hub for KavachOS.

## Setup Steps

### 1. Enable Discussions

In repository settings:
1. Go to **Settings** → **General** → **Features**
2. Check **Discussions**
3. (Optional) Link to existing Q&A forum or disable if using only new Discussions

### 2. Create Discussion Categories

Set up these category templates in **Settings** → **Discussions** → **Categories**:

#### 📢 Announcements
- **Intent:** Breaking changes, releases, security patches
- **Format:** Maintainer-only posts pinned for 2 weeks
- **Pinned:** "Release v1.0.0", "Security Advisory", "Roadmap Q2 2026"
- **Auto-pin:** Top 2 posts (new releases, critical security)

#### 🤔 Q&A  
- **Intent:** How-to questions, API usage, troubleshooting
- **Format:** Questions marked answered when solution confirmed
- **Ping:** Assign to `@area-expert` tags for routing (e.g., @adapters-expert, @cli-expert)
- **Stale:** Auto-close unanswered after 60 days with courtesy link to Support SLA

#### 💡 Ideas & Feedback
- **Intent:** Feature requests, API design feedback, RFCs
- **Format:** Proposer outlines use case; reactions gauge community interest
- **Voting:** React with 👍 for support; top 5 ideas weekly in maintainer check-in
- **Outcome:** Move **Ideas** → **Announcements** once approved for roadmap

#### 🐛 Bug Reports & Troubleshooting (Optional)
- **Intent:** If you want to triage some bugs via Discussions first
- **Format:** Use templates from `.github/ISSUE_TEMPLATE/` but direct here first
- **Route:** Maintainer assessment → files GitHub Issue if reproducible + confirmed
- **Note:** Can be disabled if using Issues exclusively

#### 🏗️ Development & Contributing
- **Intent:** Contributing workflow questions, open PRs for feedback, release management
- **Format:** Links to CONTRIBUTING.md, Changeset workflow, Release checklist
- **Access:** Visible to all, but maintainers respond to maintainer-specific posts
- **Pinned:** "How to contribute", "Release cycle timeline", "Become a maintainer"

#### ❓ General
- **Intent:** Meta discussions not fitting above
- **Format:** All sizes; good for brainstorming and off-topic
- **Moderation:** Keep focused on KavachOS; link to code-of-conduct for violations

### 3. Automation Rules (via GitHub Actions)

```yaml
# .github/workflows/discussions-triage.yml
name: Triage Discussions
on:
  discussions:
    types: [created, reopened]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Add Welcome Comment to New Discussions
        if: github.event.action == 'created'
        uses: actions/github-script@v7
        with:
          script: |
            const discussion = context.payload.discussion.body_html;
            const category = context.payload.discussion.category.name;
            
            let welcomeMsg = '';
            if (category.includes('Q&A')) {
              welcomeMsg = '👋 Thanks for the question! A maintainer will respond within 2 business days. In the meantime, check [Discussions](https://github.com/kavachos/kavachos/discussions) for similar Q&A.';
            } else if (category.includes('Ideas')) {
              welcomeMsg = '💡 Great idea! React with 👍 to show support. Our team reviews top ideas weekly.';
            } else if (category.includes('Bug')) {
              welcomeMsg = '🔍 Thanks for reporting! If reproducible, we\'ll file a GitHub Issue. See [troubleshooting guide](./docs/).';
            }
            
            github.rest.discussions.createComment({
              repository_id: context.payload.repository.id,
              discussion_number: context.payload.discussion.number,
              body: welcomeMsg
            });
```

### 4. Pinned Announcements (Create Once)

#### 📌 "Welcome to KavachOS Community"
```
# Welcome to KavachOS Discussions! 👋

This is our primary space for:
- **Q&A:** How do I...? | Troubleshooting | Usage patterns
- **Ideas:** Feature requests | Design feedback | RFCs
- **Announcements:** Releases | Security updates | Maintainer updates
- **Contributing:** Release cycle | Roadmap | Becoming a maintainer

## Quick Links
- 📖 [Contributing Guide](https://github.com/kavachos/kavachos/blob/main/CONTRIBUTING.md)
- 🛡️ [Security Policy](https://github.com/kavachos/kavachos/blob/main/SECURITY.md)
- 📋 [Roadmap & Ideas](https://github.com/kavachos/kavachos/discussions/categories/ideas-feedback)
- 💬 [Real-time chat](https://discord.gg/kavachos)

**Issues?** Check [Support Channels](./SUPPORT.md).
```

#### 📌 "Release v1.0.0 — First Stable Release"
```
# 🎉 Release v1.0.0 — First Stable Release

**Released:** March 29, 2026

## What's New
- 15 adapters reaching stable status
- Dashboard UI overhaul
- new CLI tools

## Migration Guide
See [CHANGELOG.md](./CHANGELOG.md) and [Upgrade Guide](./docs/upgrading.md).

**Questions?** Ask in the 📢 Announcements thread or 🤔 Q&A.
**Issues?** File a [GitHub Issue](https://github.com/kavachos/kavachos/issues).
```

#### 📌 "Roadmap & Future Direction"
```
# 🗺️ Roadmap 2026

## Q1 Focus
- ✅ Stable adapters (v1.0.0)
- 🚧 Plugin system public beta
- 🚧 Managed service offering

## Q2 Ideas (Vote 👍)
- GraphQL federation experiment
- Dashboard mobile PWA
- Community plugin marketplace

**Your Ideas:** [Ideas Discussion](https://github.com/kavachos/kavachos/discussions/categories/ideas-feedback)
```

## Maintenance Workflow

### Daily (15 min)

```
1. Check Question Backlog (Q&A category)
   - Sort by "Needs Answers"  
   - Mark answered questions with 💬 reaction + "This answers your question" comment
   - Pin recurring FAQs to category description

2. Moderate New Posts
   - Remove off-topic or duplicate posts with model comment pointing to existing discussion

3. Route Bug Reports
   - "This looks like a reported bug" → link to GitHub Issue
   - "This needs more info" → template with repro steps request
   - "Confirmed + new" → convert to GitHub Issue draft
```

### Weekly (1 hour)

```
1. Top Ideas Review
   - Sort Ideas by reactions (👍 count)
   - Top 3: reply "This is on our Q2 roadmap, thank you"
   - Top 5-10: reply "We're tracking this, PRs welcome if you want to contribute"

2. Community Highlights
   - Pin 1 helpful answer & thank the contributor
   - Share in project Discord/Twitter

3. Stale Discussion Cleanup
   - Close Q&A with no answer after 60 days (bot auto-comment with Support SLA link)
   - Archive completed feature discussions
```

### Monthly (2 hours)

```
1. Metrics Review
   - GitHub Discussions > Insights
   - Track: Q&A response time, idea velocity, engagement delta

2. Category Refinement
   - Rename if needed; add sub-categories if > 50 discussions
   - Archive low-traffic categories

3. Communicator Roundtable (async)
   - Link to top ideas, questions, contributors
   - Send to maintainers for visibility
```

## Best Practices

### Questions/Discussions

✅ **Do:**
- Ask one question per discussion thread (easy to search & find answer later)
- Include minimal reproducible example (MRE) for bugs/questions
- React to helpful responses with 👍
- Search similar questions before posting

❌ **Don't:**
- Cross-post same question to Issues & Discussions (pick one)
- Bikeshed design decisions in Discussions (escalate to RFC issue)
- Share API keys, tokens, or secrets (edit post + notify maintainer)

### Moderating/Responding

✅ **Do:**
- Respond within 2 business days (per SUPPORT.md SLA)
- Link related GitHub Issues for context
- Acknowledge good contributions: "Thanks for the thorough MRE!"
- Move off-topic to general category

❌ **Don't:**
- Let unanswered Q&A pile up > 2 weeks
- Dismiss polite feedback without explanation
- Cross-post answers to Twitter/Discord without permission

## Example Discussion Flows

### "How to use Adapter X?"
- Poster asks in Q&A
- Maintainer responds with code snippet + link to adapter docs
- Poster replies "Thanks!" + marks as answered
- Maintainer reacts with 👍

### "Feature: Plugin marketplace"
- Poster creates Idea with use case
- Community reacts with 👍 (now +47 reactions)
- Monthly review: maintainer says "High interest, roadmap for Q3"
- Link to related GitHub Issue for tracking

### "Bug: CLI crashes on Windows"
- Poster reports in Bug category with repro steps
- Maintainer: "Can you share output of `glinr --version` and your OS details?"
- Poster replies + maintainer confirms
- Maintainer: "Filing GitHub Issue now, thanks for the MRE"
- Maintainer file issue #1234, auto-link in discussion
- Close discussion with "See Issue #1234"

## Integration with Other Channels

| Channel | Use For | Link |
|---------|---------|------|
| GitHub Issues | Confirmed bugs, features with spec | `/github/issues`|
| GitHub Discussions | Q&A, ideas, feedback, discussion | `/discussions` |
| Discord | Real-time chat, community bonding | `http://discord.gg/kavachos` |
| Support Email | Security, abuse, escalations | `support@kavachos.dev` |

## Escalation Paths

```
Discussions → Issues
- "I'm interested in this feature/bug, should I file an issue?"
- Maintainer: "Yes, please! Use this template: [link]"

Issues → Discussions  
- Author of GitHub Issue: "For design feedback before I implement"
- Use: Ping to Discussions ideas category

Discussions → Discord
- For urgent security: Pin announcement + Discord notification
- For roadmap: Weekly recap in #announcements discord channel
```
