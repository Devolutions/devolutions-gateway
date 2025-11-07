## Project Overview

Devolutions Gateway is a relay server.
The project is a polyglot monorepo containing:
- **Rust workspace**: gateway service, agent service, jetsocat CLI tool, and dedicated testsuite
- **TypeScript/Angular pnpm workspace**: web UI with multiple packages and apps
- **C# desktop agent**: Windows-specific agent implementation
- **PowerShell module**: management and configuration tools

## Guidelines

### Rust (Required before submitting)
```bash
cargo +nightly fmt --all
cargo clippy --workspace --tests -- -D warnings
cargo test --workspace
```
- Pedantic Clippy lints are enabled; THINK before suppressing.
- Use `#[expect(clippy::<lint_name>, reason = "<explain why>")]` with clear reasoning.
- Tests go in `testsuite/tests/`, helpers in `testsuite/src/`.
- Consider `proptest` for property-based testing, `rstest` for parameterized tests.

### TypeScript/JavaScript (webapp/)
```bash
pnpm install
pnpm fmt:write
pnpm lint
pnpm test
```

### PowerShell
```bash
powershell/build.ps1
powershell/run-tests.ps1
```

### C#/.NET
Follow standard .NET conventions.

## Git Workflow

### Branch Naming
Use one of these formats:
- **Jira ticket**: `DGW-338` (ticket ID as branch name) with optional description (e.g.: `DGW-338-websocket-compression-support`)
- **GitHub issue**: Follow standard format (e.g., `fix/123-description`)

### Pull Request Guidelines

#### PR Title (Conventional Commits)
Format: `<type>(<scope>): <description>`

**Scopes** (what appears in CHANGELOG.md):
- `dgw` - Devolutions Gateway service
- `agent` - Devolutions Agent service and artifacts
- `jetsocat` - Jetsocat CLI tool
- `webapp` - Devolutions Gateway standalone frontend ONLY

**Library scopes** (excluded from changelog):
- `dotnet-*` - .NET libraries (e.g., `dotnet-utils`)
- `ts-*` - TypeScript libraries (e.g., `ts-client`)
- `*deps*`, `*openapi*`, `*npm*` - Dependency updates

**Types**:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `style:` Code style (formatting, semicolons, etc)
- `refactor:` Code restructuring without behavior change
- `perf:` Performance improvements
- `test:` Adding missing tests
- `build:` Build system or dependencies
- `ci:` CI configuration
- `chore:` Maintenance tasks

#### PR Body
- User-oriented description (what users gain/notice)
- Can include technical context for developers
- Avoid internal implementation details
- Focus on impact and benefits
- This text appears in the changelog for feat/fix/perf

#### PR Footer
Always include issue reference:
```
Issue: DGW-123  (Jira ticket)
Issue: #456     (GitHub issue)
```

#### Implementation Details
Add a **separate comment** after PR creation with:
- Technical implementation details
- Design decisions and trade-offs
- Testing approach
- Breaking changes or migration notes
- Any context helpful for reviewers

#### Example PR
```
Title: feat(dgw): add WebSocket compression support

Body:
Adds support for per-message deflate compression on WebSocket connections,
reducing bandwidth usage by up to 70% for typical JSON payloads. This
significantly improves performance for users on limited bandwidth connections.

Issue: DGW-338
```

Then add comment:
```
Implementation notes:
- Uses permessage-deflate extension (RFC 7692)
- Configurable compression level (1-9, default: 6)
- Memory pool for deflate contexts to avoid allocations
- Benchmarks show 15% CPU increase for 70% bandwidth reduction
```

#### Example PR (Library - not in changelog)
```
Title: fix(ts-client): handle reconnection timeout properly

Body:
Fixes an issue where the TypeScript client library would not properly
handle reconnection timeouts, causing infinite connection attempts.

Issue: DGW-422
```

## Code Style

### Rust
Follow the [IronRDP style guide](https://github.com/Devolutions/IronRDP/blob/master/STYLE.md).
These guidelines summarize the key points for this project.

#### Errors
- **Return types**: Use `crate_name::Result` (e.g., `anyhow::Result`), not bare `Result`.
  Exception: when type alias is clear (e.g., `ConnectionResult`).

- **Error messages**: lowercase, no punctuation, one sentence.
  - ✅ `"invalid X.509 certificate"`
  - ❌ `"Invalid X.509 certificate."`

#### Logging (not errors!)
- **Log messages**: Capital first letter, no period.
  - ✅ `info!("Connect to RDP host");`
  - ❌ `info!("connect to RDP host.");`

- Use structured fields: `info!(%server_addr, "Looked up server address");`
- Name fields consistently: use `error` not `e` for errors.

#### Comments
- **Inline comments**: Full sentences with capital and period.
  - ✅ `// Install a very strict rule to ensure tests are limited.`
  - ❌ `// make sure tests can't do just anything`
  - Exception: brief tags (`// VER`, `// RSV`) don't need periods.

- **Size calculations**: Comment each field
  ```rust
  const FIXED_PART_SIZE: usize =
      1 /* Version */ +
      1 /* Endianness */ +
      2 /* CommonHeaderLength */ +
      4 /* Filler */;
  ```

- **Invariants**:
  - Define with `// INVARIANT: …`
  - Loop invariants: before the loop
  - Field invariants: in doc comments
  - Function output invariants: in function doc comments
  - When referencing in `#[expect(...)]`: don't use `INVARIANT:` prefix

- **Markdown**: For prose paragraphs, use one sentence per line in `.md` files.

### TypeScript/JavaScript
Follow Angular style guide for components.

### PowerShell
Follow standard PowerShell conventions.

## Additional Resources
- Main README: `README.md`
- Changelog: `CHANGELOG.md`
- Style guide: `STYLE.md`
- Web app: `webapp/README.md`
- Configuration: `config_schema.json`
- Cookbook: `docs/COOKBOOK.md`
