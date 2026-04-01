---
name: toolbox-changelog
description: Generates user-facing changelogs for Devolutions Gateway and Devolutions Agent in Devolutions ToolBox format from CHANGELOG.md.
compatibility:
  tools:
    - Bash
    - Read
---

# ToolBox Changelog Generator

Read `CHANGELOG.md` from the project root and produce two user-facing changelogs — one for **Devolutions Gateway** and one for **Devolutions Agent** — ready to paste into the Devolutions ToolBox change history.

## Step 1: Determine the target version

- If the user provided a version argument (e.g. `/toolbox-changelog 2025.3.4`), find the `## 2025.3.4 (...)` block in CHANGELOG.md.
- Otherwise, use the **first** (most recent) version block in the file.

## Step 2: Collect relevant entries

For each entry in the target version block, check the scope (the text in `_italics_` before the colon). An entry can have multiple scopes separated by commas (e.g. `_dgw,agent_:`).

**Scope routing:**

| Scope          | Product              | Label       |
|----------------|----------------------|-------------|
| `dgw`          | Devolutions Gateway  | `Service`   |
| `installer`    | Devolutions Gateway  | `Installer` |
| `agent`        | Devolutions Agent    | `Service`   |
| `agent-installer` | Devolutions Agent | `Installer` |

Ignore entries with any other scope (`webapp`, `jetsocat`, `build`, etc.) — they are internal or belong to other products.

When a single entry has multiple scopes (e.g. `_dgw,agent_:`), emit a separate line for each product it belongs to.

## Step 3: Classify into categories

Map each CHANGELOG section to a user-facing category:

| CHANGELOG section | Category      |
|-------------------|---------------|
| `### Features`    | New features  |
| `### Performance` | Improvements  |
| `### Security`    | Improvements  |
| `### Bug Fixes`   | Fixes         |
| `### Build`       | *(skip)*      |

If unsure, use your judgment: new capabilities → New features, polish/performance/UX → Improvements, fixes → Fixes.

## Step 4: Write user-friendly descriptions

The raw commit message title is often too technical. Rewrite each entry in plain English that a non-developer end user would understand:

- Remove implementation details (crate names, internal module names, PR numbers, commit hashes, protocol internals).
- Use active voice and plain language.
- Preserve the key user-visible benefit.
- Keep it to one line.

**Good examples:**
- `Service - Add options to use a dedicated certificate for CredSSP credential injection`
- `Installer - Allow downloading keys even when the certificate isn't trusted (useful in restricted/air-gapped environments)`
- `Service - Reduce noisy logs: benign client disconnects are now logged as DEBUG instead of ERROR`
- `Service - Add outbound proxy configuration support for HTTP/HTTPS and SOCKS`
- `Service - Automatically generate a self-signed certificate for CredSSP when no TLS certificate is configured`

**Bad examples (too technical):**
- `Service - Replace reqwest system-proxy with proxy_cfg crate for PAC file support` ← internal implementation detail
- `Service - Downgrade BrokenPipe/ConnectionReset/UnexpectedEof from ERROR to DEBUG` ← raw code terms
- `Installer - Fix 9a9f31ad71` ← commit hash, no context

Use the multi-line description under each entry (when present) to understand the user-facing impact — but don't reproduce it verbatim; summarize what the user gains.

**Handling vague entries:** When a commit message title is ambiguous and there is no multi-line description, inspect the commit diff to understand what actually changed. Each CHANGELOG entry contains a commit hash as a link — run `git show <hash>` to read the diff. Use what you find to write an accurate, user-friendly description. Only omit an entry if the diff confirms it is purely internal with no user-visible effect.

## Step 5: Output format

Print the final result. Omit any category that has no entries.

```
Devolutions Gateway

New features
Service - ...
Installer - ...

Improvements
Service - ...

Fixes
Service - ...
Installer - ...

---

Devolutions Agent

New features
Service - ...

Improvements
Service - ...

Fixes
Service - ...
Installer - ...
```

Each entry is on its own line. Categories are separated by a blank line. The two product sections are separated by `---` and a blank line. This makes it easy to copy individual lines directly into the Devolutions ToolBox.
