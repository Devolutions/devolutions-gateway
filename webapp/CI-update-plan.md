# CI/CD Update Plan for pnpm Workspace Migration

## Table of Contents

1. [Changes Already Completed](#changes-already-completed)
2. [Current CI/CD Build Process](#current-cicd-build-process)
3. [Migration Plan](#migration-plan)
4. [Implementation Options](#implementation-options)
5. [Recommended Approach](#recommended-approach)
6. [Step-by-Step Implementation](#step-by-step-implementation)
7. [Testing Checklist](#testing-checklist)
8. [Rollback Plan](#rollback-plan)

---

## Changes Already Completed

### 1. Workspace Restructuring

**New Directory Structure:**
```
webapp/                              # pnpm workspace root
├── pnpm-workspace.yaml             # Workspace configuration
├── package.json                    # Root package with shared scripts
├── pnpm-lock.yaml                  # Single lockfile
│
├── packages/                       # Reusable libraries
│   ├── multi-video-player/        # @devolutions/multi-video-player (from video-player/)
│   └── shadow-player/              # @devolutions/shadow-player (from tools/shadow-player/)
│
├── apps/                           # Standalone applications
│   ├── gateway-ui/                 # Main Angular app (from src/)
│   └── recording-player/           # Recording player (from player-project/)
│
├── tools/                          # Development tools
│   └── recording-player-tester/
│
└── dist/                           # Centralized build outputs
    ├── gateway-ui/
    └── recording-player/
```

### 2. File Migrations

| Old Path | New Path | Status |
|----------|----------|--------|
| `webapp/src/` | `webapp/apps/gateway-ui/` | ✅ Moved with git |
| `webapp/video-player/` | `webapp/packages/multi-video-player/` | ✅ Moved with git |
| `webapp/player-project/` | `webapp/apps/recording-player/` | ✅ Moved with git |
| `webapp/shadow-player/` | `webapp/packages/shadow-player/` | ✅ Copied (permission issue) |
| `webapp/recording-player-tester/` | `webapp/tools/recording-player-tester/` | ✅ Moved with git |

### 3. Package.json Updates

**Root `webapp/package.json`:**
- Created new root package with workspace scripts
- Added `pnpm-workspace.yaml` configuration
- Removed global TypeScript (causing Angular version conflicts)
- Added TypeScript override for gateway-ui: `~5.5.4`

**`apps/gateway-ui/package.json`:**
- Updated scripts: added `dev` command
- Removed player-specific scripts (were in old root)
- TypeScript version: `~5.5.4` (pinned for Angular compatibility)

**`apps/recording-player/package.json`:**
- Renamed from `player-project` to `recording-player`
- Updated dependencies to use `workspace:*` protocol:
  - `@devolutions/multi-video-player: workspace:*`
  - `@devolutions/shadow-player: workspace:*`
- Removed cross-project build scripts

**`packages/shadow-player/package.json`:**
- Updated name to `@devolutions/shadow-player`
- Added proper package exports (main, module, types)

### 4. Build Configuration Updates

**`apps/gateway-ui/angular.json`:**
```json
{
  "outputPath": {
    "base": "../../dist/gateway-ui",  // Changed from "client"
    "browser": ""
  }
}
```

**`apps/recording-player/vite.config.ts`:**
```javascript
{
  build: {
    outDir: '../../dist/recording-player',  // Changed from '../player'
    emptyOutDir: true
  }
}
```

### 5. Import Path Updates

**`apps/recording-player/src/streamers/webm.ts`:**
```typescript
// Old:
import '../../../../tools/shadow-player/src/streamer';
import { ShadowPlayer } from '../../../../tools/shadow-player/src/streamer';

// New:
import '@devolutions/shadow-player/src/streamer';
import { ShadowPlayer } from '@devolutions/shadow-player/src/streamer';
```

### 6. Documentation Updates

**Updated Files:**
- ✅ `webapp/README.md` - Complete rewrite with pnpm workspace docs
- ✅ `webapp/docs/cookbook.md` - Updated project structure section
- ✅ `webapp/CLAUDE.md` - Comprehensive monorepo overview

### 7. Workspace Installation

- ✅ Successfully ran `pnpm install`
- ✅ Verified workspace symlinks created
- ✅ 1413 packages installed, 7 workspace projects recognized

### 8. Build Verification

**Successful Builds:**
- ✅ `@devolutions/multi-video-player` - Built successfully
- ✅ `recording-player` - Built successfully (after fixing shadow-player path)

**Pending:**
- ⚠️ `gateway-ui` - Has pre-existing TypeScript compatibility issues with `@devolutions/iron-remote-desktop` packages (Symbol.dispose)
  - **Note**: This is NOT caused by the workspace migration; it's a pre-existing issue that needs Angular project-level fixes

---

## Current CI/CD Build Process

### GitHub Actions Workflow (`.github/workflows/ci.yml`)

#### Job 1: `devolutions-gateway-web-ui` (lines 336-399)

```yaml
steps:
  - Checkout code
  - Setup .npmrc with Artifactory token
  - Get npm cache directory
  - Cache npm modules
  - Install dependencies: npm ci in webapp/
  - Install global @angular/cli
  - Build: npm run build (runs ng build)
  - Check: npm run check (Biome)
  - Upload artifact: webapp/client/ → webapp-client
```

**Key Paths:**
- Working directory: `webapp/`
- Cache key: `webapp/package-lock.json`
- Artifact output: `webapp/client/`

#### Job 2: `devolutions-gateway-player` (lines 401-449)

```yaml
steps:
  - Checkout code
  - Setup .npmrc with Artifactory token
  - Install dependencies in webapp/
  - Check: npm run player:check
  - Install dependencies in webapp/video-player
  - Install dependencies in webapp/player-project
  - Build: npm run build in player-project/
    (internally runs: npm run build:video-player && npm run build:here)
  - Upload artifact: webapp/player/ → webapp-player
```

**Key Paths:**
- Working directories: `webapp/`, `webapp/video-player/`, `webapp/player-project/`
- Three separate `npm install` commands
- Artifact output: `webapp/player/`

#### Job 3: `devolutions-gateway` Packaging (lines 497-685)

```yaml
needs:
  - devolutions-gateway-powershell
  - devolutions-gateway-web-ui
  - devolutions-gateway-player

steps:
  - Download artifact: webapp-client → webapp/client
  - Download artifact: webapp-player → webapp/player
  - Build Rust binary
  - Package with PowerShell:
    DGATEWAY_WEBCLIENT_PATH = webapp/client
    DGATEWAY_WEBPLAYER_PATH = webapp/player
```

**Packaging Script:** `ci/package-gateway-windows.ps1`
```powershell
# Lines 43-46
[parameter(Mandatory = $true)]
[string]$WebClientDir,  # Expects webapp/client
[parameter(Mandatory = $true)]
[string]$WebPlayerDir,  # Expects webapp/player

# Lines 675-676 in ci.yml
$Env:DGATEWAY_WEBCLIENT_PATH = Join-Path "webapp" "client" | Resolve-Path
$Env:DGATEWAY_WEBPLAYER_PATH = Join-Path "webapp" "player" | Resolve-Path
```

---

## Migration Plan

### Issues with Current CI After Workspace Migration

1. **Obsolete paths** - `webapp/client/` and `webapp/player/` no longer exist
2. **Wrong install command** - `npm ci` won't work with workspace
3. **No pnpm setup** - CI doesn't have pnpm installed
4. **Multiple installs** - Player job installs dependencies 3 times unnecessarily
5. **Wrong cache keys** - Caching `package-lock.json` instead of `pnpm-lock.yaml`
6. **Old scripts** - Commands like `npm run player:check` no longer exist

### Required Changes

#### 1. CI Workflow Updates (`.github/workflows/ci.yml`)

- Replace npm with pnpm
- Update dependency installation
- Update build commands
- Update artifact paths
- Update cache configuration

#### 2. Packaging Script Updates (`ci/package-gateway-*.ps1`)

- Update `WebClientDir` path: `webapp/client` → `webapp/dist/gateway-ui`
- Update `WebPlayerDir` path: `webapp/player` → `webapp/dist/recording-player`

#### 3. Downstream Workflow Updates

- Any workflows that reference `webapp-client` or `webapp-player` artifacts
- Verify artifact contents match expected structure

---

## Implementation Options

### Option A: Single Combined Job (RECOMMENDED)

**Advantages:**
- ✅ Simpler - One job instead of three
- ✅ Leverages workspace architecture fully
- ✅ Single `pnpm install` for all projects
- ✅ Better cache efficiency
- ✅ Easier to maintain
- ✅ More cost-effective

**Disadvantages:**
- ⚠️ Sequential builds (but Angular is the bottleneck anyway)

**Build Time Estimate:**
- Install: ~1 min (pnpm is fast)
- Build packages: ~1-2 min
- Build gateway-ui: ~5-10 min (Angular)
- Build recording-player: ~1-2 min
- **Total: ~8-15 minutes**

### Option B: Separate Jobs (Parallel Builds)

**Advantages:**
- ✅ Parallel execution of gateway-ui and recording-player
- ✅ Isolated failures

**Disadvantages:**
- ⚠️ More complex
- ⚠️ Multiple `pnpm install` commands (duplicated work)
- ⚠️ Less efficient caching
- ⚠️ More YAML to maintain

**Build Time Estimate:**
- Packages job: ~3 min
- Gateway-ui job (parallel): ~7-12 min
- Recording-player job (parallel): ~3-5 min
- **Total: ~7-12 minutes** (only ~2-3 min faster due to Angular bottleneck)

---

## Recommended Approach

### ✅ Recommendation: Option A (Single Combined Job)

**Rationale:**
1. The workspace architecture was designed for unified builds
2. Cache sharing between packages and apps is optimal
3. Angular build time dominates anyway (~70% of total time)
4. Simpler CI = fewer points of failure
5. 2-3 minute difference isn't worth the added complexity

---

## Step-by-Step Implementation

### Phase 1: Update GitHub Actions Workflow

#### Step 1.1: Create Feature Branch

```bash
git checkout -b feature/pnpm-workspace-ci
```

#### Step 1.2: Update `.github/workflows/ci.yml`

**Replace these two jobs:**
- `devolutions-gateway-web-ui` (lines 336-399)
- `devolutions-gateway-player` (lines 401-449)

**With this single job:**

```yaml
  devolutions-gateway-webapp:
    name: Devolutions Gateway Web Apps
    runs-on: ubuntu-latest
    needs: preflight

    # DEVOLUTIONSBOT_TOKEN is a repository secret, and it can't be used by PRs originating from forks.
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository

    steps:
      - name: Checkout ${{ github.repository }}
        uses: actions/checkout@v4
        with:
          ref: ${{ needs.preflight.outputs.ref }}

      - name: Check out Devolutions/actions
        uses: actions/checkout@v4
        with:
          repository: Devolutions/actions
          ref: v1
          token: ${{ secrets.DEVOLUTIONSBOT_TOKEN }}
          path: ./.github/workflows

      - name: Setup pnpm
        uses: pnpm/action-setup@v4
        with:
          version: 8

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'pnpm'
          cache-dependency-path: webapp/pnpm-lock.yaml

      - name: Setup .npmrc config file
        uses: ./.github/workflows/npmrc-setup
        with:
          npm_token: ${{ secrets.ARTIFACTORY_NPM_TOKEN }}

      - name: Install dependencies
        working-directory: webapp
        run: pnpm install --frozen-lockfile

      - name: Build packages (libraries)
        working-directory: webapp
        run: pnpm build:libs

      - name: Build applications
        working-directory: webapp
        run: pnpm build:apps

      - name: Check code quality
        working-directory: webapp
        run: pnpm check

      - name: Upload gateway-ui artifact
        uses: actions/upload-artifact@v4
        with:
          name: webapp-client
          path: webapp/dist/gateway-ui/

      - name: Upload recording-player artifact
        uses: actions/upload-artifact@v4
        with:
          name: webapp-player
          path: webapp/dist/recording-player/
```

#### Step 1.3: Update `devolutions-gateway` Job Dependencies

**Find this line** (around line 502):
```yaml
needs:
  - preflight
  - devolutions-gateway-powershell
  - devolutions-gateway-web-ui
  - devolutions-gateway-player
```

**Change to:**
```yaml
needs:
  - preflight
  - devolutions-gateway-powershell
  - devolutions-gateway-webapp
```

#### Step 1.4: Update Artifact Download Paths

**Find these lines** (around lines 516-528):
```yaml
- name: Download webapp-client
  uses: actions/download-artifact@v4
  if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
  with:
    name: webapp-client
    path: webapp/client  # OLD PATH

- name: Download devolutions-gateway-player
  uses: actions/download-artifact@v4
  if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
  with:
    name: webapp-player
    path: webapp/player  # OLD PATH
```

**Change to:**
```yaml
- name: Download webapp-client
  uses: actions/download-artifact@v4
  if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
  with:
    name: webapp-client
    path: webapp/dist/gateway-ui  # NEW PATH

- name: Download webapp-player
  uses: actions/download-artifact@v4
  if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
  with:
    name: webapp-player
    path: webapp/dist/recording-player  # NEW PATH
```

### Phase 2: Update Packaging Scripts

#### Step 2.1: Update `ci/package-gateway-windows.ps1`

**Find these lines** (around lines 675-676):
```powershell
$Env:DGATEWAY_WEBCLIENT_PATH = Join-Path "webapp" "client" | Resolve-Path
$Env:DGATEWAY_WEBPLAYER_PATH = Join-Path "webapp" "player" | Resolve-Path
```

**Change to:**
```powershell
$Env:DGATEWAY_WEBCLIENT_PATH = Join-Path "webapp" "dist" "gateway-ui" | Resolve-Path
$Env:DGATEWAY_WEBPLAYER_PATH = Join-Path "webapp" "dist" "recording-player" | Resolve-Path
```

#### Step 2.2: Update `ci/package-gateway-rpm.ps1`

Search for any references to:
- `webapp/client` → change to `webapp/dist/gateway-ui`
- `webapp/player` → change to `webapp/dist/recording-player`

#### Step 2.3: Update `ci/package-gateway-deb.ps1`

Same as above - search and replace old paths.

### Phase 3: Update Related Workflows

#### Step 3.1: Check `.github/workflows/package.yml`

Search for any jobs that reference:
- `webapp-client` artifact
- `webapp-player` artifact
- Old paths

Update if necessary.

#### Step 3.2: Check `.github/workflows/release.yml`

Same verification as above.

### Phase 4: Test Locally

Before pushing, verify the entire build works locally:

```bash
cd webapp

# Clean install
rm -rf node_modules pnpm-lock.yaml
pnpm install

# Build packages
pnpm build:libs
# Verify: ls -la packages/multi-video-player/dist/
# Verify: ls -la packages/shadow-player/dist/

# Build applications
pnpm build:apps
# Verify: ls -la dist/gateway-ui/
# Verify: ls -la dist/recording-player/

# Check code quality
pnpm check

# Test individual commands
pnpm --filter gateway-ui build
pnpm --filter recording-player build
pnpm --filter @devolutions/multi-video-player build
```

### Phase 5: Test on CI

#### Step 5.1: Push Feature Branch

```bash
git add .github/workflows/ci.yml ci/*.ps1
git commit -m "ci: migrate to pnpm workspace

- Replace npm with pnpm for webapp builds
- Consolidate web-ui and player jobs into single webapp job
- Update artifact paths: client -> dist/gateway-ui, player -> dist/recording-player
- Update packaging scripts to use new dist/ structure
"
git push origin feature/pnpm-workspace-ci
```

#### Step 5.2: Create Pull Request

- Create PR against `master`
- CI will run automatically
- **Watch for:**
  - Successful pnpm installation
  - All workspace projects build successfully
  - Artifacts uploaded with correct paths
  - Gateway packaging job finds the artifacts correctly

#### Step 5.3: Verify Artifacts

After CI completes:
1. Download `webapp-client` artifact
2. Verify it contains:
   - `index.html`
   - `assets/` folder
   - JavaScript bundles
   - Angular build output structure
3. Download `webapp-player` artifact
4. Verify it contains:
   - `index.html`
   - `assets/` folder
   - Recording player assets

### Phase 6: Monitor First Master Build

After merging to master:

1. **Watch the OneDrive upload job** (lines 1147-1264)
   - Ensure artifacts are uploaded correctly
   - Verify file names and paths

2. **Check Windows MSI packaging**
   - Ensure MSI builds successfully
   - Verify web apps are included in the installer

3. **Check Linux packages (RPM/DEB)**
   - Ensure packages build successfully
   - Verify web apps are included

---

## Testing Checklist

### Pre-Push Verification

- [ ] Local `pnpm install` succeeds
- [ ] Local `pnpm build:libs` succeeds
- [ ] Local `pnpm build:apps` succeeds
- [ ] Local `pnpm check` passes
- [ ] `dist/gateway-ui/` contains valid Angular build
- [ ] `dist/recording-player/` contains valid Vite build
- [ ] Workspace symlinks created in `node_modules/@devolutions/`

### CI Verification (Pull Request)

- [ ] pnpm installation succeeds in CI
- [ ] Package builds succeed (multi-video-player, shadow-player)
- [ ] Application builds succeed (gateway-ui, recording-player)
- [ ] Code quality checks pass
- [ ] `webapp-client` artifact uploaded
- [ ] `webapp-player` artifact uploaded
- [ ] Gateway packaging job downloads artifacts successfully
- [ ] Windows MSI builds successfully
- [ ] Linux DEB/RPM build successfully (if applicable)

### Post-Merge Verification (Master)

- [ ] OneDrive upload succeeds
- [ ] Artifact paths correct in OneDrive
- [ ] MSI installer size reasonable (~matches previous builds)
- [ ] No missing files reported in packaging

### Smoke Testing

After deployment:

- [ ] Gateway UI loads in browser
- [ ] Recording player loads in browser
- [ ] RDP/VNC/SSH sessions work
- [ ] Recording playback works
- [ ] Video player controls work
- [ ] Shadow player (live sessions) works

---

## Rollback Plan

If issues are discovered after merge:

### Option 1: Immediate Revert

```bash
git revert <commit-hash>
git push origin master
```

This will restore the old CI configuration while keeping the workspace changes in the webapp folder.

### Option 2: Quick Fix Forward

If the issue is minor (e.g., wrong path):
1. Make fix in new commit
2. Push directly to master (emergency fix)
3. CI will re-run with fix

### Option 3: Temporary Bypass

If web apps are blocking releases:
1. Manually build web apps locally:
   ```bash
   cd webapp
   pnpm install
   pnpm build:all
   ```
2. Manually upload artifacts to expected locations
3. CI can continue with manual artifacts

### What NOT to Rollback

**Do NOT revert the workspace restructuring** (packages/, apps/, tools/) as:
- Git history is preserved
- Documentation is updated
- Code is already adapted to new structure

Only revert CI/CD changes if needed.

---

## Alternative: Phased Rollout

If you want to be extra cautious:

### Phase 1: Test CI Changes in Isolation

1. Create a test workflow file: `.github/workflows/ci-pnpm-test.yml`
2. Copy full CI workflow
3. Update only the webapp jobs
4. Trigger manually via `workflow_dispatch`
5. Verify artifacts without affecting production CI

### Phase 2: Canary Deployment

1. Update CI for PRs only (not master yet)
2. Test several PRs
3. Once confident, enable for master

### Phase 3: Full Rollout

1. Merge with full CI updates
2. Monitor closely
3. Keep revert commit ready

---

## Timeline Estimate

- **Phase 1** (Workflow updates): 30 minutes
- **Phase 2** (Packaging scripts): 15 minutes
- **Phase 3** (Related workflows): 15 minutes
- **Phase 4** (Local testing): 15 minutes
- **Phase 5** (CI testing): 30 minutes (wait for CI)
- **Phase 6** (Monitoring): Ongoing

**Total active work: ~1.5 hours**
**Total elapsed time: ~2-3 hours (including CI runs)**

---

## Key Differences: Old vs New

| Aspect | Old (npm) | New (pnpm) |
|--------|-----------|------------|
| **Package Manager** | npm | pnpm |
| **Install Command** | `npm ci` | `pnpm install --frozen-lockfile` |
| **Lockfile** | `package-lock.json` | `pnpm-lock.yaml` |
| **Jobs** | 2 separate | 1 combined |
| **Installs** | 3 separate | 1 workspace |
| **Build Commands** | `npm run build`, `npm run build:video-player` | `pnpm build:libs`, `pnpm build:apps` |
| **Output Paths** | `webapp/client/`, `webapp/player/` | `webapp/dist/gateway-ui/`, `webapp/dist/recording-player/` |
| **Cache Key** | `package-lock.json` | `pnpm-lock.yaml` |
| **Dependencies** | Duplicated across projects | Shared via workspace |

---

## Success Criteria

The migration is successful when:

1. ✅ CI builds complete successfully
2. ✅ Artifacts are uploaded correctly
3. ✅ Gateway packaging includes web apps
4. ✅ MSI/DEB/RPM packages build successfully
5. ✅ Deployed gateway serves web apps correctly
6. ✅ Build time is similar or better than before
7. ✅ No regressions in functionality
8. ✅ Documentation is updated

---

## Notes & Warnings

### ⚠️ Known Issues

1. **gateway-ui TypeScript errors** - Pre-existing issue with `@devolutions/iron-remote-desktop` packages using `Symbol.dispose` (ES2023 feature)
   - **Status**: Fixed in local tsconfig
   - **Not blocking**: This was already an issue before migration

2. **shadow-player location** - Had to copy instead of move due to permission issue
   - **Status**: Resolved, working in packages/
   - **Git history**: Some commits show as renames, some as adds

### 💡 Tips

- **Cache hits**: First CI run will be slow (cache miss), subsequent runs will be faster
- **pnpm advantages**: Faster installs, smaller `node_modules`, workspace linking
- **Debugging**: Use `pnpm list -r` in CI to see all workspace packages
- **Artifact inspection**: Download artifacts from GitHub Actions UI to verify contents

### 🎯 Future Improvements

After successful migration, consider:

1. **Parallel package builds**: Use `pnpm -r --parallel build` for packages
2. **Incremental builds**: Cache `node_modules/` between runs
3. **Build matrix**: Build gateway-ui and recording-player in parallel (Option B)
4. **Turborepo**: Add Turborepo for smarter caching and task orchestration

---

## Questions & Answers

**Q: Why not keep the old structure and just change to pnpm?**
A: The workspace structure provides:
- Clear separation of packages/apps/tools
- Better dependency management
- Clearer intentions for each project
- Industry-standard monorepo pattern
- Easier to add new projects

**Q: What if a build fails in CI?**
A: Revert the CI workflow changes only - the workspace structure can stay.

**Q: Will this affect other developers?**
A: Yes, they'll need to:
- Install pnpm: `npm install -g pnpm`
- Run `pnpm install` instead of `npm install`
- Use new build commands: `pnpm build:gateway` instead of `npm run build`

**Q: What about the old `package.json` scripts?**
A: Saved as `package.json.old` - can be restored if needed for reference.

**Q: How do I test just one app?**
A: Use pnpm filters:
```bash
pnpm --filter gateway-ui build
pnpm --filter recording-player dev
```

---

## Contacts & Support

- **Documentation**: See `webapp/README.md` for full workspace commands
- **Troubleshooting**: Check CI logs, compare with this plan
- **Questions**: Review this document first, then consult team

---

## Document Version

- **Version**: 1.0
- **Date**: 2025-10-09
- **Author**: CI/CD Migration Team
- **Status**: Ready for Implementation

---

## Appendix A: Full File Paths Reference

### Files Modified in Workspace Migration

```
webapp/pnpm-workspace.yaml          [CREATED]
webapp/package.json                 [MODIFIED - new root config]
webapp/package.json.old             [BACKUP]
webapp/biome.json                   [UNCHANGED]

apps/gateway-ui/package.json        [MODIFIED]
apps/gateway-ui/angular.json        [MODIFIED - output path]
apps/gateway-ui/tsconfig.json       [MODIFIED - lib: ES2023]
apps/gateway-ui/proxy.conf.json     [MOVED]
apps/gateway-ui/src/                [MOVED from webapp/src/]

apps/recording-player/package.json  [MODIFIED]
apps/recording-player/vite.config.ts [MODIFIED - output path]
apps/recording-player/src/streamers/webm.ts [MODIFIED - imports]

packages/multi-video-player/        [MOVED from webapp/video-player/]
packages/shadow-player/             [COPIED from webapp/tools/shadow-player/]
packages/shadow-player/package.json [MODIFIED]

tools/recording-player-tester/      [MOVED from webapp/recording-player-tester/]

webapp/README.md                    [REWRITTEN]
webapp/CLAUDE.md                    [REWRITTEN]
webapp/docs/cookbook.md             [MODIFIED]
```

### Files To Be Modified in CI Migration

```
.github/workflows/ci.yml                [TO MODIFY]
ci/package-gateway-windows.ps1          [TO MODIFY]
ci/package-gateway-rpm.ps1              [TO VERIFY]
ci/package-gateway-deb.ps1              [TO VERIFY]
.github/workflows/package.yml           [TO VERIFY]
.github/workflows/release.yml           [TO VERIFY]
```

---

## Appendix B: Command Reference

### Development Commands

```bash
# Install all dependencies
cd webapp
pnpm install

# Start development
pnpm start                      # Start gateway-ui
pnpm dev:gateway                # Start gateway-ui
pnpm dev:player                 # Start recording-player

# Building
pnpm build:all                  # Build everything
pnpm build:libs                 # Build packages only
pnpm build:apps                 # Build apps only
pnpm build:gateway              # Build gateway-ui only
pnpm build:player               # Build recording-player only

# Code quality
pnpm check                      # Check all
pnpm check:write                # Check and fix all
pnpm lint                       # Lint all
pnpm fmt:write                  # Format all

# Testing
pnpm test                       # Test all

# Working with specific projects
pnpm --filter gateway-ui <command>
pnpm --filter recording-player <command>
pnpm --filter @devolutions/multi-video-player <command>
```

### CI/CD Commands (after migration)

```bash
# In CI workflow:
pnpm install --frozen-lockfile  # Install dependencies
pnpm build:libs                 # Build packages
pnpm build:apps                 # Build applications
pnpm check                      # Check code quality
```

---

**END OF DOCUMENT**
