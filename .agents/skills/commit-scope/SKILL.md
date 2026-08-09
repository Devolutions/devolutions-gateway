---
name: commit-scope
description: Select commit and PR scopes in the Devolutions Gateway repository. Use whenever composing or reviewing a Conventional Commit subject, especially for shared libraries, packaging, tests, documentation, CI, or changes spanning products.
---

# Devolutions Gateway commit scope

Choose scopes by affected deliverable, not file location or internal component.

1. Inspect the diff and repository instructions.
2. Read the ordered parsers in `cliff.toml`; the completed subject and footers determine whether git-cliff includes the commit.
3. For an included commit, trace shared-code and packaging dependencies to every affected product. For Rust crates, inspect reverse dependencies. Count shipped normal dependencies; ignore dev-only use unless tests or developer behavior are the change.
4. Add every applicable product scope:

| Scope | Area |
|---|---|
| `dgw` | Devolutions Gateway service, runtime, API, configuration, or product-specific tests/docs/build logic |
| `installer` | Devolutions Gateway installers, packages, installation behavior, or installer-specific tests/docs/build logic |
| `agent` | Devolutions Agent services, updater, runtime, or product-specific tests/docs/build logic |
| `agent-installer` | Devolutions Agent installers, packages, installation behavior, or installer-specific tests/docs/build logic |
| `jetsocat` | Jetsocat runtime, packages, or product-specific tests/docs/build logic |
| `webapp` | Anything affecting the standalone Gateway web application |

A shared component receives each product scope whose behavior changes. Merely bundling an updated runtime does not add `installer` or `agent-installer`; add those scopes only when installation or packaging behavior changes. Do not use internal component names such as `jmux` or `pedm`: JMUX changes commonly affect `dgw,jetsocat`; PEDM changes commonly affect `agent` and sometimes `agent-installer`.

For included commits, use only product scopes. Scopes containing `openapi`, `npm`, `nuget`, `dotnet-*`, or `ts-*` cause git-cliff to suppress the entry. The `deps` scope suppresses only exact `chore(deps)` and `build(deps)` subjects; do not use it with other included types or as part of a broader scope.

Scopes are more flexible when git-cliff excludes the commit, whether by type, scope, or `Changelog: ignore`. Keep the semantic type: an npm package feature may use `feat(npm): ...` because the scope suppresses it. For `chore`, `ci`, `style`, `refactor`, and `test`, use a concise target when useful, such as `openapi`, `deps`, `toolchain`, `package`, `agents`, `dependabot`, `miri`, `tokengen`, or `dotnet-utils`; omit the scope if none helps. Prefer a precise current name over generic `tools` or `dotnet`.
Use `agents` for agent instructions and reusable skills.

Use the established `chore(release): prepare for <version>` pattern when cutting a release.

For multiple products, separate scopes with commas and no spaces in this order: `dgw,installer,agent,agent-installer,jetsocat,webapp`.

Examples:

- Shared code shipped by Gateway and Agent: `fix(dgw,agent): ...`
- JMUX code shared by Gateway and Jetsocat: `perf(dgw,jetsocat): ...`
- Standalone web application change: `feat(webapp): ...`
- Gateway contract plus generated clients: `feat(dgw): ...`
- Standalone npm package feature: `feat(npm): ...`
- Generated clients only: `chore(openapi): ...`
- Release preparation: `chore(release): prepare for 2026.3.0`
