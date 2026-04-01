# prepare-release

Prepares a Devolutions Gateway / Devolutions Agent release commit: bumps the version, generates and inserts the changelog, creates Jira tickets, generates the ToolBox changelog, and produces the final release commit.

## Prerequisites

### git-cliff

Used to generate unreleased changelog entries from conventional commits.

```bash
cargo install git-cliff
```

Or via a pre-built binary: <https://github.com/orhun/git-cliff/releases>

### PowerShell 7+

Used by the version bump script.

```powershell
winget install Microsoft.PowerShell
```

### changelog-to-jira prerequisites

This skill calls `/changelog-to-jira` internally. All of its prerequisites must also be satisfied:

- **JiraPS module** — `Install-Module JiraPS -Scope CurrentUser`
- **Atlassian API token** — generate at <https://id.atlassian.com/manage-profile/security/api-tokens> with scopes `read:jira-work` and `write:jira-work`
- **Environment variables** in your PowerShell profile (`$PROFILE`):

  ```powershell
  $env:JIRA_URL       = "https://devolutions.atlassian.net"
  $env:JIRA_EMAIL     = "you@devolutions.net"
  $env:JIRA_API_TOKEN = "your-api-token-here"
  ```

- **Atlassian MCP server** configured in Claude Code:

  ```bash
  claude mcp add --transport sse claude_ai_Atlassian https://mcp.atlassian.com/v1/sse
  ```
