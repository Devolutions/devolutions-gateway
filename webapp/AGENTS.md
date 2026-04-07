# AGENTS.md

## Scope and intent
- This repo is a `pnpm` monorepo (`pnpm-workspace.yaml`) with three lanes: `apps/*` (deployable apps), `packages/*` (reusable web components), and `tools/*` (dev utilities).
- Build outputs are centralized under `dist/` (see `README.md` and each Vite/Angular config).

## Architecture map (what talks to what)
- `apps/gateway-ui` is the Angular admin UI; it proxies backend calls to Gateway at `http://localhost:7171` in dev via `apps/gateway-ui/proxy.conf.json`.
- `apps/recording-player` is a Vite app that decides playback mode from URL params (`sessionId`, `token`, `isActive`, `lang`) in `apps/recording-player/src/main.ts`.
- `recording-player` consumes workspace packages: `@devolutions/multi-video-player` (static multi-file WebM playback) and `@devolutions/shadow-player` (live stream via MSE/WebSocket).
- `packages/multi-video-player` wraps video.js as `<multi-video-player>`; it fetches `/jet/jrec/pull/.../recording.json` and segment files (`src/gateway-api.ts`).
- `packages/shadow-player` defines `<shadow-player>` and streams chunks over `/jet/jrec/shadow/:sessionId?token=...` (`src/streamer.ts`).
- `tools/recording-player-tester` is a React helper app that mints tokens and opens player URLs for manual testing.

## High-value code paths
- Playback routing: `apps/recording-player/src/main.ts`, `apps/recording-player/src/players/index.ts`, `apps/recording-player/src/streamers/index.ts`.
- Gateway URL construction: `apps/recording-player/src/gateway.ts`, `packages/multi-video-player/src/gateway-api.ts`.
- WebSocket close interception shim: `apps/recording-player/src/ws-proxy.ts` (normalizes close handling for asciinema-player behavior).
- Angular protocol/session wiring: `apps/gateway-ui/src/client/app/shared/services/web-session.service.ts` and `.../enums/web-client-protocol.enum.ts`.
- Protocol extension cookbook: `docs/cookbook.md` (authoritative for adding new protocol form + session component wiring).

## Developer workflows (repo root)
- Install: `pnpm install`.
- Dev servers: `pnpm dev:gateway` (Angular), `pnpm dev:player` (recording player).
- Build all: `pnpm build:all`; build libs only: `pnpm build:libs`; apps only: `pnpm build:apps`.
- Quality gates: `pnpm check` and `pnpm check:write` (Biome across workspaces).
- Tests: `pnpm test` runs `--if-present`; some projects (for example `apps/recording-player`) currently define no test script.

## Project-specific conventions
- Formatting/linting is Biome-first (not ESLint/Prettier); follow root `biome.json` and project overrides.
- TS import aliases in Angular use `@gateway/*` and `@shared/*` (`apps/gateway-ui/tsconfig.json`).
- Web components are registered by side-effect imports, then awaited with `customElements.whenDefined(...)` before method calls (see `apps/recording-player/src/players/webm.ts`, `.../streamers/webm.ts`).
- URL/token patterns are part of runtime contract; preserve `/jet/jrec/pull`, `/jet/jrec/play`, `/jet/jrec/shadow`, and query `token` behavior when refactoring.
- Root `.node-version` pins Node `20.18.3`; README minimum is Node >= 18. Prefer matching `.node-version` locally/CI.

## Existing AI guidance discovery
- Searched: `**/{.github/copilot-instructions.md,AGENT.md,AGENTS.md,CLAUDE.md,.cursorrules,.windsurfrules,.clinerules,.cursor/rules/**,.windsurf/rules/**,.clinerules/**,README.md}`.
- Found in-repo guidance docs: `README.md`, `packages/multi-video-player/README.md`.
- No other agent-rule files from that glob were present at generation time.

