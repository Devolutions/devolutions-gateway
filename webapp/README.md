# Devolutions Gateway Web Applications

This is a **pnpm workspace** monorepo containing multiple TypeScript/JavaScript projects for the Devolutions Gateway web interface and media players.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Getting Started](#getting-started)
- [Development](#development)
- [Building](#building)
- [Project Structure](#project-structure)
- [Workspace Commands](#workspace-commands)

## Architecture Overview

The workspace is organized into three main categories:

- **packages/**: Reusable library components (can be published to npm)
- **apps/**: End-user applications
- **tools/**: Internal development utilities

### Projects

#### Applications (`apps/`)

**gateway-ui** - Main Angular administrative interface
- Angular 18.2 application
- Manages gateway configuration and settings
- Supports RDP/VNC/SSH/Telnet/ARD protocols via web browser
- Uses PrimeNG for UI components
- Development server: http://localhost:4200/jet/webapp/client/

**recording-player** - Recording player application
- Complete web application for playing various recording formats
- Supports WebM videos, terminal sessions (.cast), TRP files
- Live session shadowing via WebSocket
- Built with Vite + TypeScript

#### Packages (`packages/`)

**@devolutions/multi-video-player** - Reusable video player component
- Video.js-based web component
- Sequential multi-video playback with unified controls
- Distributable npm package

**@devolutions/shadow-player** - Live session shadowing component
- Web component for real-time session streaming
- Used by recording-player for live shadowing

#### Tools (`tools/`)

**recording-player-tester** - Testing utility
- React-based test app for recording player
- File upload and local testing

## Getting Started

### Prerequisites

- **Node.js** >= 18.0.0
- **pnpm** >= 8.0.0

### Installation

```bash
# Install pnpm globally if you haven't already
npm install -g pnpm

# Install all workspace dependencies
pnpm install
```

This will install dependencies for all projects in the workspace and create symlinks between internal packages.

## Development

### Start Development Servers

```bash
# Start gateway-ui dev server
pnpm dev:gateway
# or
pnpm start

# Start recording-player dev server
pnpm dev:player
```

### Development for Specific Projects

To run commands in a specific project:

```bash
# Run any command in a specific workspace
pnpm --filter gateway-ui <command>
pnpm --filter recording-player <command>
pnpm --filter @devolutions/multi-video-player <command>

# Examples:
pnpm --filter gateway-ui dev
pnpm --filter recording-player build
pnpm --filter @devolutions/multi-video-player test
```

### Linting and Formatting

All projects use **Biome** for linting and formatting (not ESLint/Prettier).

```bash
# Check all projects
pnpm check

# Auto-fix all projects
pnpm check:write

# Format all projects
pnpm fmt:write
```

## Building

### Build All Projects

```bash
# Build everything
pnpm build:all

# Build only packages
pnpm build:libs

# Build only applications
pnpm build:apps
```

### Build Individual Projects

```bash
# Build gateway-ui
pnpm build:gateway

# Build recording-player
pnpm build:player

# Build multi-video-player package
pnpm --filter @devolutions/multi-video-player build
```

### Build Outputs

All build outputs are stored in the centralized `dist/` directory:

```
webapp/
└── dist/
    ├── gateway-ui/          # Angular production build
    ├── recording-player/    # Vite production build
    └── packages/
        └── multi-video-player/  # Library build
```

## Project Structure

```
webapp/                              # pnpm workspace root
├── pnpm-workspace.yaml             # Workspace configuration
├── package.json                    # Root package with shared scripts
├── pnpm-lock.yaml                  # Single lockfile for entire workspace
│
├── packages/                       # Reusable libraries
│   ├── multi-video-player/        # @devolutions/multi-video-player
│   │   ├── src/
│   │   ├── dist/
│   │   ├── package.json
│   │   └── vite.config.ts
│   └── shadow-player/              # @devolutions/shadow-player
│       ├── src/
│       └── package.json
│
├── apps/                           # Standalone applications
│   ├── gateway-ui/                 # Main Angular admin interface
│   │   ├── src/
│   │   ├── angular.json
│   │   ├── package.json
│   │   └── proxy.conf.json
│   └── recording-player/           # Recording player app
│       ├── src/
│       ├── package.json
│       └── vite.config.ts
│
├── tools/                          # Development & testing tools
│   └── recording-player-tester/
│       └── package.json
│
└── dist/                           # All build outputs (gitignored)
    ├── gateway-ui/
    ├── recording-player/
    └── packages/
```

## Workspace Commands

### Root-level Commands

From the workspace root (`webapp/`):

| Command | Description |
|---------|-------------|
| `pnpm start` | Start gateway-ui dev server |
| `pnpm dev:gateway` | Start gateway-ui dev server |
| `pnpm dev:player` | Start recording-player dev server |
| `pnpm build:all` | Build all projects |
| `pnpm build:libs` | Build packages only |
| `pnpm build:apps` | Build apps only |
| `pnpm build:gateway` | Build gateway-ui only |
| `pnpm build:player` | Build recording-player only |
| `pnpm check` | Run biome check on all projects |
| `pnpm check:write` | Run biome check with auto-fix |
| `pnpm lint` | Lint all projects |
| `pnpm lint:write` | Lint with auto-fix |
| `pnpm fmt` | Check formatting |
| `pnpm fmt:write` | Format all code |
| `pnpm test` | Run tests for all projects |

### Working with Individual Projects

```bash
# Filter commands to specific projects
pnpm --filter <project-name> <command>

# Examples:
pnpm --filter gateway-ui start
pnpm --filter recording-player dev
pnpm --filter @devolutions/multi-video-player build

# Run command in all packages
pnpm --filter './packages/**' build

# Run command in all apps
pnpm --filter './apps/**' build

# Run command recursively in all projects
pnpm -r <command>
```

### Workspace Dependencies

Internal packages use the `workspace:*` protocol:

```json
{
  "dependencies": {
    "@devolutions/multi-video-player": "workspace:*",
    "@devolutions/shadow-player": "workspace:*"
  }
}
```

pnpm automatically creates symlinks to local packages during `pnpm install`.

## Testing

```bash
# Run all tests
pnpm test

# Run tests for specific project
pnpm --filter gateway-ui test
pnpm --filter @devolutions/multi-video-player test
```

### Testing Recording Player with local Devolutions Gateway & DVLS

To test the recording player with your locally running Devolutions Gateway:

#### 1. Build Dependencies

```bash
# From webapp/ directory
# Build the required packages first
pnpm --filter @devolutions/multi-video-player build
pnpm --filter @devolutions/shadow-player build
```

#### 2. Build the Recording Player

```bash
# From webapp/ directory
pnpm build:player
```

This creates production-ready files in `webapp/dist/recording-player/`.

#### 3. Copy Files to Gateway

```powershell
# Windows PowerShell - Copy to your Gateway's release directory
New-Item -ItemType Directory -Force -Path target\release\webapp\player
Copy-Item -Recurse -Force webapp\dist\recording-player\* target\release\webapp\player\
```

```bash
# Linux/macOS
mkdir -p target/release/webapp/player
cp -r webapp/dist/recording-player/* target/release/webapp/player/
```

#### 4. Run Gateway with Environment Variable

```powershell
# Windows PowerShell
$env:DGATEWAY_WEBAPP_PATH = 'E:\path\to\devolutions-gateway\target\release\webapp'
& "E:\path\to\devolutions-gateway\target\release\devolutions-gateway.exe"
```

```bash
# Linux/macOS
export DGATEWAY_WEBAPP_PATH=/path/to/target/release/webapp
/path/to/target/release/devolutions-gateway
```

#### 5. Access the Player

The recording player is now accessible through your localhost DVLS via the local Devolutions Gateway.

**Note:** After making changes to the recording player, rebuild with `pnpm build:player` and restart the Gateway to see the changes.

## Technologies

- **Angular** 18.2 (gateway-ui)
- **Vite** 6.x (recording-player, packages)
- **TypeScript** 5.5+ (all projects)
- **Biome** 2.0 (linting and formatting)
- **PrimeNG** 17.x (UI components)
- **Video.js** 8.x (video player)
- **pnpm** 8.0+ (package management)

## Additional Documentation

- [Development Cookbook](./docs/cookbook.md) - Detailed guide for adding protocols and form controls
- [Project CLAUDE.md](./CLAUDE.md) - AI assistant context and project relationships

## Notes

- **Migration**: This workspace was migrated from a flat npm structure to pnpm workspaces for better dependency management and build performance.
- **Angular CLI**: The Angular CLI is available within `apps/gateway-ui` and can be accessed via `pnpm --filter gateway-ui ng <command>`.
- **Parallel Builds**: Use `pnpm -r --parallel build` for faster parallel builds (use with caution).
