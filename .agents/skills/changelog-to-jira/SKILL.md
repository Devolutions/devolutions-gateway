---
name: changelog-to-jira
description: Creates missing DGW Jira tickets from CHANGELOG.md entries and updates the file with the new ticket links.
---

# Changelog to Jira Skill

This skill reads `CHANGELOG.md`, identifies entries that don't have a `DGW-*` Jira ticket, groups similar entries together, creates them in the DGW project, infers the assignee from the commit author, transitions them to Done, and updates `CHANGELOG.md` with the new ticket links.

## Scope

**Only process entries for these components** (text inside `_italics_`):
- `dgw` — Devolutions Gateway core
- `installer` — Devolutions Gateway installer
- `agent` — Devolutions Agent
- `agent-installer` — Agent installer

Skip entries for any other component (e.g., `webapp`, `jetsocat`, `crates`).

**Always default to the latest release** — the first `## VERSION (DATE)` block in the file.

## Audience

Ticket descriptions are for **QA technicians, support technicians, and marketing people**. Write them from a consumer perspective — what changed for the user, not how it was implemented. Avoid internal code references, crate names, and architecture notes.

**Length:** calibrate to the complexity of the change.
- A bug fix or minor improvement: 1–2 sentences is enough.
- A new feature that requires configuration or has non-obvious behaviour: write as much as needed. Include what the feature does, how to enable or configure it, and any relevant defaults or caveats. This gives QA and support enough context to test and explain it without needing to read the code.

**Examples:**

Bug fix (short):
> Fixed a crash that could occur when the Gateway service was restarted while an active session was recording.

New feature needing configuration (longer):
> Gateway and Agent now support outbound proxy configuration for all network traffic. The proxy mode is controlled by the `Proxy.Mode` field in the configuration file:
> - `System` (default): auto-detects proxy settings from environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) or system settings (WinHTTP on Windows, `/etc/sysconfig/proxy` on RHEL/SUSE, system preferences on macOS).
> - `Manual`: uses explicitly configured URLs. Set `Proxy.Http`, `Proxy.Https`, or `Proxy.All` to a proxy URL (e.g. `http://proxy.corp:8080` or `socks5://proxy.corp:1080`).
> - `Off`: disables proxy entirely.
>
> HTTP, HTTPS, SOCKS4, and SOCKS5 proxies are supported.

## Workflow

### Step 1: Read and Parse CHANGELOG.md

Read `CHANGELOG.md` from the current working directory. Take the first `## VERSION (DATE)` block.

**Entry format:**
```
## VERSION (DATE)

### Section (Features / Bug Fixes / Security / Performance / etc.)

- _component_: short description ([#PR](github-pr-url)) ([commit](commit-url)) ([TICKET-ID](jira-url))

  Optional multi-line body with more detail.
```

Parse each entry into:
- `section`: Features / Bug Fixes / Security / Performance / etc.
- `component`: text inside `_italics_`
- `description`: the short description text
- `body`: optional indented multi-line description
- `github_pr`: PR number if present (e.g., `#1676`)
- `commit_hash`: short hash from the commit URL if present
- `existing_tickets`: all Jira ticket IDs found (pattern: `[A-Z]+-\d+` with `atlassian.net/browse` URL)

Filter to only entries whose `component` is one of: `dgw`, `installer`, `agent`, `agent-installer`.

### Step 2: Classify and Group Entries

#### Classify each entry

| Case | Condition | Action |
|---|---|---|
| **Already done** | Has a `DGW-*` ticket | Skip |
| **Cross-project** | Has a ticket from another project (e.g., `ARC-353`, `PI-651`) | Create a DGW ticket linked to the original |
| **Missing** | No Jira ticket | Create a new DGW ticket |

#### Group similar entries into a single ticket

Before planning ticket creation, look for entries that describe **the same underlying change** and should be represented by one ticket rather than several. Group them when:

- They share the same PR number (most reliable signal — same code change, multiple components affected)
- They are clearly two sides of the same feature (e.g., both `dgw` and `agent` entries describe adding the same capability)
- The descriptions are semantically equivalent (same fix or feature, slightly different wording)

When grouping, create **one ticket** that:
- Lists all affected components in the summary: `[dgw, agent] Feature description`
- Has a description that covers all components
- Maps CHANGELOG.md lines for all grouped entries to this single ticket

Do not force groupings. When in doubt, create separate tickets.

### Step 3: Show the Plan

Before creating anything, show a summary table and wait for confirmation:

```
Latest release: 2026.1.0 (2026-02-23)

Will CREATE (no ticket):
  [Features] dgw: Add CredSSP certificate configuration keys (#1676)
  [Bug Fixes] agent-installer: Specify ARM64 platform for ARM64 installer

Will CREATE (grouped — same change):
  [Features] dgw + agent: RDM pipe passthrough logic (#1701)
    • dgw: add pipe passthrough for RDM
    • agent: handle pipe passthrough messages from RDM

Will CREATE + LINK (cross-project ticket):
  [Features] agent: RDM messages and pipe passthrough logic → PI-651

Already have DGW tickets (skipping):
  DGW-341 — Improve real-time performance of session shadowing

Proceed?
```

### Step 4: Infer Assignee from Commit Author

For every entry that needs a new ticket (missing or cross-project), infer the assignee by looking up the commit author in git and resolving them to a Jira account.

**For entries with a commit hash:**

```bash
git log --format="%ae %an" -1 <commit-hash>
```

This gives you the author's email and name. Then look up their Jira account:

```
mcp__claude_ai_Atlassian__lookupJiraAccountId  →  query = "<author email or name>"
```

Use the email first — it's the most reliable identifier. If no match, try the display name.

**For cross-project entries:** Also fetch the original ticket's assignee (`getJiraIssue → assignee.accountId`) as a fallback if the commit lookup yields no result. Prefer the commit author when both are available.

**If no commit hash is available**, or the author lookup returns no result, omit the assignee field — do not block ticket creation.

**Cache the results** — if two entries share the same commit author, reuse the resolved `accountId` without a second lookup.

### Step 5: Build the ticket plan and run the script

Construct a `jira-plan.json` file in the repo root with all tickets to create:

```json
{
  "tickets": [
    {
      "id": "t1",
      "summary": "[dgw] Add CredSSP certificate configuration keys",
      "issuetype": "Story",
      "description": "Consumer-facing description. Length should match complexity — see Audience section.",
      "assignee_account_id": "557058:eeb3e2d6-ef7a-463e-9d9e-5834dd925adb",
      "cross_project_link": null
    },
    {
      "id": "t2",
      "summary": "[dgw, agent] RDM pipe passthrough logic",
      "issuetype": "Bug",
      "description": "...",
      "assignee_account_id": null,
      "cross_project_link": "PI-651"
    }
  ]
}
```

**Issue type by section:**
| Section | `issuetype` |
|---|---|
| Features | `Story` |
| Bug Fixes | `Bug` |
| Security | `Bug` |
| Performance | `Story` |
| Other | `Task` |

**Summary format:** `[component] Capitalized short description`
- Single entry: `[dgw] Add CredSSP certificate configuration keys`
- Grouped entry: `[dgw, agent] Add CredSSP certificate configuration keys`

**Description:** 2–4 sentences, consumer-facing. Rewrite for a non-technical audience. For cross-project entries, append: `Related ticket: ARC-353`.

Keep a local map of `id → CHANGELOG.md line(s)` — you will need it in Step 7 to write back the ticket keys.

Then run the script, capturing its JSON output:

```powershell
pwsh <skill-dir>/scripts/invoke-jira.ps1 -PlanFile jira-plan.json
```

The script handles everything mechanical: creating each ticket, linking cross-project tickets, walking the DGW workflow to Done (`Backlog → To Do → Development → Reviewing → Done`), and deleting `jira-plan.json` when done.

The result JSON is written to stdout:

```json
{
  "created": [
    { "id": "t1", "key": "DGW-400" },
    { "id": "t2", "key": "DGW-401" }
  ],
  "errors": []
}
```

If `errors` is non-empty, report the failures to the user before continuing.

### Step 7: Update CHANGELOG.md

After creating all tickets, automatically update `CHANGELOG.md` to append the new ticket links to each affected entry line.

Entry format for the appended link: `([DGW-400](https://devolutions.atlassian.net/browse/DGW-400))`

It goes at the end of the `-` line, after existing links. For grouped entries, add the same ticket link to **all** the CHANGELOG.md lines that were grouped together. Example:

Before:
```
- _dgw_: add CredSSP certificate configuration keys ([#1676](...)) ([443e5f0b02](...))
```
After:
```
- _dgw_: add CredSSP certificate configuration keys ([#1676](...)) ([443e5f0b02](...)) ([DGW-400](https://devolutions.atlassian.net/browse/DGW-400))
```

### Step 8: Summary Report

```
Created N DGW tickets for version 2026.1.0:
  DGW-400: [dgw] Add CredSSP certificate configuration keys  (assignee: Alice)
  DGW-401: [agent-installer] Specify ARM64 platform for ARM64 installer  (assignee: Bob)
  DGW-402: [dgw, agent] RDM pipe passthrough logic (grouped 2 entries)  (assignee: Carol)
  DGW-403: [agent] RDM messages and pipe passthrough logic (→ PI-651)  (assignee: Dave)

All tickets transitioned to Done.

Skipped 1 (already had DGW ticket):
  DGW-341 — Improve real-time performance of session shadowing

CHANGELOG.md updated with new ticket links.
```

## Edge Cases

- **Multi-component entries** like `_dgw,agent_`: Process it (both components are in scope), use the combined form in the summary.
- **No body text**: Write a 1-sentence description from the summary alone — don't leave it blank.
- **Unknown link type**: Call `mcp__claude_ai_Atlassian__getIssueLinkTypes` to find "relates to".
- **Unknown issue types**: Call `mcp__claude_ai_Atlassian__getJiraProjectIssueTypesMetadata` for project `DGW`.
- **Commit author not in Jira**: If `lookupJiraAccountId` returns no results (e.g., a contractor or external contributor), skip the assignee — don't block ticket creation.
- **No "Done" transition**: If the project uses different terminal state names, pick the closest one. If genuinely ambiguous, skip transitioning and note it in the summary.

## Atlassian MCP Tools

These are the only MCP tools still needed — ticket creation, linking, and transitions are handled by the PowerShell script.

- `mcp__claude_ai_Atlassian__lookupJiraAccountId` — resolve a commit author's email or name to a Jira account ID (Step 4)
- `mcp__claude_ai_Atlassian__getJiraIssue` — fetch cross-project ticket details (assignee fallback, Step 4)
- `mcp__claude_ai_Atlassian__searchJiraIssuesUsingJql` — search existing tickets if needed
