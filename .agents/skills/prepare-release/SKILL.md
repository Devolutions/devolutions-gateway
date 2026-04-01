---
name: prepare-release
description: Prepares a Devolutions Gateway / Devolutions Agent release commit: bumps the version, generates and inserts the changelog, creates Jira tickets, generates the ToolBox changelog, and produces the final release commit.
compatibility:
  tools:
    - Bash
    - Read
    - Edit
    - mcp__claude_ai_Atlassian__lookupJiraAccountId
    - mcp__claude_ai_Atlassian__getJiraIssue
    - mcp__claude_ai_Atlassian__searchJiraIssuesUsingJql
---

# Prepare Release Skill

This skill walks through every step needed to produce the `chore(release): prepare for <VERSION>` commit for Devolutions Gateway and Devolutions Agent.

> The user is responsible for creating and checking out the release branch beforehand. This skill does **not** create or switch branches.

---

## Step 1: Determine the target version

Run the bundled script to resolve the version, passing the user's argument (if any):

```powershell
# From the repo root:
pwsh <skill-dir>/scripts/resolve-version.ps1 -Arg "<ARGUMENT>"
```

The script prints the resolved version to stdout and exits with:
- **0** — version resolved successfully; use the printed string.
- **1** — error (malformed VERSION file or bad argument); report and stop.
- **2** — no argument was provided; the script prints the *current* version. In this case ask the user: "What version are we releasing? Current is `<printed version>`. You can type an explicit version (e.g. `2026.2.0`), or `minor` / `major`." Then re-run the script with their answer.

Show the resolved version to the user and wait for confirmation before proceeding.

---

## Step 2: Bump the version

Run the PowerShell bump script from the repo root:

```powershell
./tools/bump-version.ps1 -NewVersion <VERSION>
```

This updates `VERSION`, `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock`, the `.csproj`, `.psd1`, `AppxManifest.xml`, **and** the two Linux packaging changelogs (`package/Linux/CHANGELOG.md`, `package/AgentLinux/CHANGELOG.md`). No further changes to those files are needed.

If the script fails (e.g. the new version equals the current version), report the error and stop.

---

## Step 3: Generate unreleased changelog entries

Run git-cliff to get the entries that haven't been released yet:

```bash
git cliff --unreleased
```

The output starts with `## [Unreleased]` followed by section headers (`### Features`, `### Bug Fixes`, etc.) and individual bullet entries.

---

## Step 4: Insert the changelog into CHANGELOG.md

Open `CHANGELOG.md`. The file begins with:

```
# Changelog

This document provides a list of notable changes introduced in ...

## <most recent version> (<date>)
...
```

Insert the new version block **between the introductory paragraph and the first existing `## ...` version line**.

Replace the `## [Unreleased]` header that git-cliff produced with the correct format:

```
## <VERSION> (<TODAY>)
```

where `<TODAY>` is today's date in `YYYY-MM-DD` format (e.g. `## 2026.2.0 (2026-04-01)`).

Keep the rest of the git-cliff output (section headers and bullet entries) — but apply the cleanup steps in Step 5 before writing to the file.

---

## Step 5: Clean up the generated entries

Before writing the new block to `CHANGELOG.md`, apply these improvements:

### Strip git-cliff section prefixes
git-cliff emits HTML comment sort-order prefixes in section titles (e.g. `### <!-- 1 -->Features`). Strip them so headings render cleanly: `### Features`.

### Resolve "Please Sort" entries
If git-cliff produced a `### Please Sort` section, it means those commits didn't follow the conventional-commits format. For each such entry:
1. Run `git show <commit-hash>` to inspect the diff.
2. Based on what actually changed, classify the commit into the correct section (Features, Bug Fixes, Improvements, etc.).
3. Move it there. If the commit is purely internal with no user-visible effect, remove it entirely.

If you cannot confidently classify a "Please Sort" entry after reading the diff, keep it in a `### Please Sort` section and flag it to the user at the end.

### Fix spelling mistakes
Scan all entry titles for obvious spelling errors (typos in common words, wrong capitalisation of proper nouns like "Gateway", "CredSSP", "RDP", etc.) and correct them.

### Improve unclear commit messages
If a commit title is vague (e.g. "fix issue", "update code", "misc changes"), run `git show <commit-hash>` and rewrite the entry title to accurately describe what changed — keep it concise and factual, matching the style of other entries.

### Final check
After cleanup, if there are any remaining issues you aren't confident about, briefly list them for the user after writing the file (don't block on them — just inform).

---

## Step 6: Update Linux packaging changelogs

After inserting and cleaning up the entries, check whether any of them explicitly change Linux packaging. Look for entries that:
- Fix DEB or RPM package manifests, directory layouts, or packaging scripts
- Change how the package installs, configures, or integrates with the OS (systemd units, paths, permissions, etc.)

For each such entry, add a plain-English bullet to the relevant packaging changelog(s):
- `package/Linux/CHANGELOG.md` — for changes affecting the Gateway Linux package
- `package/AgentLinux/CHANGELOG.md` — for changes affecting the Agent Linux package

The `bump-version.ps1` script already prepended a `## VERSION (DATE)\n\n- No changes.` section. Replace `- No changes.` with the actual bullets, or leave it as-is if there are genuinely no packaging-related changes.

---

## Step 7: User review of CHANGELOG.md

Before touching Jira, show the user the new version block that was written to `CHANGELOG.md` and ask them to review it:

> "Here's the changelog for **<VERSION>**. Please review it — you can edit `CHANGELOG.md` directly now if anything needs adjusting. Type **go** when you're ready to continue."

Wait for the user to type "go" (case-insensitive) before proceeding. If they send corrections or ask for specific changes, apply them to `CHANGELOG.md` first, then wait for "go" again.

---

## Step 8: Create Jira tickets

Run the `/changelog-to-jira` skill.

This reads the freshly-updated `CHANGELOG.md`, creates any missing `DGW-*` Jira tickets, links cross-project tickets, and updates `CHANGELOG.md` with the new ticket links in one go. Let that skill drive the interaction; come back here when it is finished.

---

## Step 9: Generate the ToolBox changelog

Run the `/toolbox-changelog` skill (no version argument needed — it defaults to the most recent version block, which is the one we just inserted).

Let that skill run to completion and present its output to the user.

---

## Step 10: Create the release commit

Once both sub-skills are done and the user is happy, stage all modified files and create the commit:

```bash
git add -A
git commit -m "chore(release): prepare for <VERSION>"
```

---

## Quick reference: files touched by this skill

| File | How it changes |
|------|---------------|
| `VERSION` | Bumped by `bump-version.ps1` |
| `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock` | Version bumped |
| `dotnet/DesktopAgent/DesktopAgent.csproj` | Version bumped |
| `powershell/DevolutionsGateway/DevolutionsGateway.psd1` | Version bumped |
| `crates/devolutions-pedm-shell-ext/AppxManifest.xml` | Version bumped |
| `package/Linux/CHANGELOG.md` | New section prepended by `bump-version.ps1` |
| `package/AgentLinux/CHANGELOG.md` | New section prepended by `bump-version.ps1` |
| `CHANGELOG.md` | New version block inserted; Jira ticket links added |
