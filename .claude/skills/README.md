# Claude Code skill links

The skills live in [`.agents/skills`][skills].
Claude Code discovers project skills only in `.claude/skills`, and it does not follow a symlink to that whole folder, so this folder holds one relative symlink per skill instead.
CI fails when a skill has no link here or a link points anywhere other than its skill.

## Adding a skill

Create the skill under `.agents/skills/<name>`, then link it from the repository root.

```pwsh
New-Item -ItemType SymbolicLink -Path .claude/skills/<name> -Target ../../.agents/skills/<name>
```

```bash
ln -s ../../.agents/skills/<name> .claude/skills/<name>
```

Stage both with `git add`, then run `./ci/check-skill-links.ps1` to confirm that every skill is linked; the check reads the git index, so it does not see unstaged files.

## Windows

Git checks the links out as plain text files unless symlinks are enabled, and Claude Code then finds no skills.
Enable [Developer Mode][developer-mode] so that Windows lets you create symlinks without administrator rights, then enable symlinks in Git before cloning.

```pwsh
git config --global core.symlinks true
```

In a clone made without it, run `git config core.symlinks true` in the repository, then `git checkout -- .claude/skills` to recreate the links.
In Git Bash, set `MSYS=winsymlinks:nativestrict` so that `ln -s` creates a real Windows symlink instead of a copy.

[skills]: ../../.agents/skills
[developer-mode]: https://learn.microsoft.com/windows/apps/get-started/enable-your-device-for-development
