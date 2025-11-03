# Copilot Instructions for Devolutions Gateway

## Project Overview

Devolutions Gateway is a blazing fast relay server adaptable to different protocols and desired levels of traffic inspection. The project is a polyglot codebase containing Rust (core gateway), TypeScript/Angular (web UI), C# (desktop agent), and PowerShell (management module).

## Repository Structure

- **`crates/`** - Rust workspace libraries and internal crates
- **`devolutions-gateway/`** - Main gateway server application (Rust)
- **`devolutions-agent/`** - Agent service application (Rust)
- **`devolutions-session/`** - Session management (Rust)
- **`jetsocat/`** - Network tunneling utility (Rust)
- **`webapp/`** - Web applications (Angular/TypeScript pnpm workspace)
  - `apps/gateway-ui/` - Main Angular admin interface
  - `apps/recording-player/` - Recording player application
  - `packages/` - Reusable library components
- **`dotnet/`** - C# desktop agent components
- **`powershell/`** - PowerShell module for gateway management
- **`testsuite/`** - Integration and end-to-end tests
- **`ci/`** - Build and CI/CD scripts

## Technologies

### Primary Stack
- **Rust 1.90.0** (see `rust-toolchain.toml`)
- **TypeScript/Angular 18.2** (see `webapp/`)
- **C#/.NET** (see `dotnet/`)
- **PowerShell** (see `powershell/`)

### Key Dependencies
- Rust workspace with multiple crates
- pnpm for JavaScript/TypeScript package management
- Angular with PrimeNG for UI components
- Biome for TypeScript/JavaScript formatting and linting

## Code Style and Guidelines

### Rust
- Follow the [IronRDP style guide](https://github.com/Devolutions/IronRDP/blob/master/STYLE.md) as referenced in `STYLE.md`
- Use **nightly rustfmt** for formatting: `cargo +nightly fmt --all`
- Strict clippy lints enabled (see `Cargo.toml` workspace lints)
- Key lints enforced:
  - `unwrap_used = "warn"` - Use `.expect()` with a reason instead of `.unwrap()`
  - `undocumented_unsafe_blocks = "warn"` - Document all unsafe blocks
  - Avoid `print!`, `eprint!`, and `dbg!` macros in library code
- Use `.expect()` instead of `.unwrap()` to provide meaningful error context
- Document unsafe code blocks explaining why the code is safe

### TypeScript/JavaScript
- Use Biome for formatting and linting: `pnpm check` and `pnpm lint`
- Format with `pnpm fmt:write`
- Located in `webapp/` pnpm workspace
- Follow Angular style guide for Angular components

### PowerShell
- Follow standard PowerShell conventions
- Module located in `powershell/DevolutionsGateway/`

## Building and Testing

### Rust Components

**Build:**
```bash
# Using the TLK build script
./ci/tlk.ps1 build -Platform <linux|windows|macos> -Architecture <x86_64|arm64> -CargoProfile <dev|release|production>

# Or directly with cargo
cargo build --workspace --locked
cargo build --profile production  # For production builds
```

**Test:**
```bash
# Using the TLK test script
./ci/tlk.ps1 test -Platform <linux|windows|macos> -Architecture <x86_64|arm64> -CargoProfile dev

# Or directly with cargo
cargo test --workspace --verbose --locked
```

**Lint:**
```bash
# Format check (use nightly rustfmt)
cargo +nightly fmt --all -- --check

# Format fix
cargo +nightly fmt --all

# Clippy
cargo clippy --workspace --all-targets
```

### Web Applications

**Install dependencies:**
```bash
cd webapp
pnpm install
```

**Build:**
```bash
cd webapp
pnpm build:all        # Build all apps and packages
pnpm build:gateway    # Build gateway UI only
pnpm build:player     # Build recording player only
```

**Test:**
```bash
cd webapp
pnpm test
```

**Lint and Format:**
```bash
cd webapp
pnpm check           # Check formatting and linting
pnpm check:write     # Auto-fix formatting and linting
pnpm lint            # Lint only
pnpm fmt:write       # Format only
```

**Development:**
```bash
cd webapp
pnpm dev:gateway     # Run gateway UI dev server (http://localhost:4200/jet/webapp/client/)
pnpm dev:player      # Run recording player dev server
```

### PowerShell Module

**Build:**
```bash
cd powershell
./build.ps1
```

**Test:**
```bash
cd powershell
./run-tests.ps1
```

## Common Patterns and Conventions

### Error Handling (Rust)
- Use `.expect("meaningful message")` instead of `.unwrap()`
- Return `Result<T, E>` types for fallible operations
- Use `anyhow` or custom error types for error propagation

### Testing (Rust)
- Unit tests in same file as implementation using `#[cfg(test)]`
- Integration tests in `tests/` directories
- Use `proptest` for property-based testing (available as workspace dependency)

### Configuration
- Gateway configuration uses JSON format in `gateway.json`
- Location: `%ProgramData%\Devolutions\Gateway\` (Windows), `/etc/devolutions-gateway/` (Linux)
- Can be overridden with `DGATEWAY_CONFIG_PATH` environment variable

## CI/CD

- Main CI workflow: `.github/workflows/ci.yml`
- Tests run on Linux and Windows for x86_64 architecture
- Formatting checked with nightly rustfmt
- Build profiles: `dev`, `release`, `production`
- Production profile uses LTO and strips symbols

## Dependencies

### Adding Rust Dependencies
- Add to appropriate `Cargo.toml` (workspace root or specific crate)
- Prefer workspace-level dependencies when used by multiple crates
- Run `cargo update` if needed
- Avoid wildcard dependencies (enforced by clippy)

### Adding JavaScript/TypeScript Dependencies
- Use `pnpm add <package>` in the appropriate workspace directory
- Update `pnpm-lock.yaml` by running `pnpm install`

## Important Notes

- **Rust toolchain version pinned**: Always use Rust 1.90.0 as specified in `rust-toolchain.toml`
- **Nightly rustfmt required**: Standard rustfmt will not match the project's formatting
- **Workspace structure**: This is a Cargo workspace - changes to dependencies should consider all crates
- **Platform support**: Build and test on Linux, Windows, and macOS (x86_64 and arm64 where applicable)
- **No unwrap in production**: Use `.expect()` with meaningful messages or proper error handling
- **Security**: Avoid introducing secrets or credentials in code or configuration files

## Git Hooks

Optional git hooks can be set up using:
```bash
./setup-git-hooks.sh
```

## Additional Resources

- Main README: `README.md`
- Changelog: `CHANGELOG.md`
- Style guide reference: `STYLE.md`
- Web app documentation: `webapp/README.md`
- Configuration schema: `config_schema.json`
