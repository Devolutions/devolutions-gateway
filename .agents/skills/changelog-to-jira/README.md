# changelog-to-jira

Creates missing DGW Jira tickets from `CHANGELOG.md` entries, transitions them to Done, and writes the ticket links back into the file.

## Prerequisites

### PowerShell 7+

```powershell
winget install Microsoft.PowerShell
```

### JiraPS module

```powershell
Install-Module JiraPS -Scope CurrentUser
```

### Atlassian API token

Generate one at <https://id.atlassian.com/manage-profile/security/api-tokens>.

The token must have the following Jira scopes:

| Scope | Why |
|---|---|
| `read:jira-work` | Read issues and transitions |
| `write:jira-work` | Create issues, add links, perform transitions |

### Environment variables

Add to your PowerShell profile (`$PROFILE`):

```powershell
$env:JIRA_URL       = "https://devolutions.atlassian.net"
$env:JIRA_EMAIL     = "you@devolutions.net"
$env:JIRA_API_TOKEN = "your-api-token-here"
```

### Atlassian MCP server

The skill uses the Atlassian remote MCP server for assignee lookups. Add it to Claude Code:

```bash
claude mcp add --transport sse claude_ai_Atlassian https://mcp.atlassian.com/v1/sse
```

This registers a server named `claude_ai_Atlassian`, which is the name the skill expects. On first use, Claude Code will prompt you to authenticate via OAuth.
