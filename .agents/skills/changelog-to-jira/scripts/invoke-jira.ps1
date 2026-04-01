#!/usr/bin/env pwsh
# invoke-jira.ps1
#
# Creates Jira tickets from a JSON plan, links cross-project tickets, and
# walks each ticket through the DGW workflow to Done.
# On full success, deletes the plan file; on any error, keeps it for debugging.
#
# Usage:
#   pwsh invoke-jira.ps1 -PlanFile jira-plan.json
#
# Result JSON is written to stdout.
#
# Required environment variables:
#   JIRA_URL        — e.g. https://devolutions.atlassian.net
#   JIRA_EMAIL      — your Atlassian account email
#   JIRA_API_TOKEN  — Atlassian API token (not your password)
#
# See README.md for the full input/output JSON schema and prerequisites.

param(
    [Parameter(Mandatory)] [string] $PlanFile
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1. Validate environment
# ---------------------------------------------------------------------------

$JiraUrl   = $env:JIRA_URL
$JiraEmail = $env:JIRA_EMAIL
$JiraToken = $env:JIRA_API_TOKEN

if (-not $JiraUrl -or -not $JiraEmail -or -not $JiraToken) {
    Write-Error "Missing required environment variables. Set JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN."
    exit 1
}

if (-not (Test-Path $PlanFile)) {
    Write-Error "Plan file not found: $PlanFile"
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Connect to Jira
# ---------------------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name JiraPS)) {
    Write-Error "JiraPS module is not installed. Run: Install-Module JiraPS -Scope CurrentUser"
    exit 1
}

Import-Module JiraPS -ErrorAction Stop

Set-JiraConfigServer -Server $JiraUrl

$SecureToken = ConvertTo-SecureString $JiraToken -AsPlainText -Force
$Credential  = [System.Management.Automation.PSCredential]::new($JiraEmail, $SecureToken)
New-JiraSession -Credential $Credential | Out-Null

Write-Verbose "Connected to $JiraUrl as $JiraEmail"

# ---------------------------------------------------------------------------
# 3. DGW workflow transition chain
#    Backlog(961) → To Do(861) → Development(731) → Reviewing(741) → Done
#    These IDs are stable for the DGW project. If a transition fails,
#    fetch the current transitions with Get-JiraIssueTransition and update
#    this list.
# ---------------------------------------------------------------------------

$TransitionChain = @(961, 861, 731, 741)

# ---------------------------------------------------------------------------
# 4. Process tickets
# ---------------------------------------------------------------------------

$plan = Get-Content $PlanFile -Raw | ConvertFrom-Json

$created = [System.Collections.Generic.List[hashtable]]::new()
$errors  = [System.Collections.Generic.List[hashtable]]::new()

foreach ($ticket in $plan.tickets) {
    Write-Host "`nProcessing: $($ticket.summary)"

    try {
        # --- Create the issue ---
        $issueParams = @{
            Project     = "DGW"
            Summary     = $ticket.summary
            IssueType   = $ticket.issuetype
            Description = $ticket.description
        }
        if ($ticket.assignee_account_id) {
            $issueParams["Assignee"] = $ticket.assignee_account_id
        }

        $issue = New-JiraIssue @issueParams
        Write-Host "  Created $($issue.Key)"

        # --- Link to cross-project ticket ---
        if ($ticket.cross_project_link) {
            $linkType = Get-JiraIssueLinkType | Where-Object { $_.Name -eq "Relates" } | Select-Object -First 1
            if (-not $linkType) {
                Write-Warning "  Could not find 'Relates' link type — skipping link to $($ticket.cross_project_link)"
            } else {
                $issueLink = New-JiraIssueLink -Type $linkType -OutwardIssue $ticket.cross_project_link
                Add-JiraIssueLink -Issue $issue.Key -IssueLink $issueLink
                Write-Host "  Linked $($issue.Key) → $($ticket.cross_project_link)"
            }
        }

        # --- Walk through transition chain to Done ---
        $allTransitionsSucceeded = $true
        foreach ($transId in $TransitionChain) {
            try {
                Invoke-JiraIssueTransition -Issue $issue.Key -Transition $transId
            } catch {
                Write-Warning "  Transition $transId failed for $($issue.Key): $_"
                Write-Warning "  Remaining transitions skipped — ticket may need manual progression."
                $allTransitionsSucceeded = $false
                break
            }
        }
        if ($allTransitionsSucceeded) {
            Write-Host "  Transitioned $($issue.Key) to Done"
        } else {
            Write-Host "  Did not fully transition $($issue.Key) to Done"
        }

        $created.Add(@{ id = $ticket.id; key = $issue.Key })
    }
    catch {
        Write-Warning "  FAILED: $_"
        $errors.Add(@{ id = $ticket.id; summary = $ticket.summary; error = "$_" })
    }
}

# ---------------------------------------------------------------------------
# 5. Clean up plan file and output results
# ---------------------------------------------------------------------------

if ($errors.Count -eq 0) {
    try {
        Remove-Item -LiteralPath $PlanFile -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to delete plan file '$PlanFile': $_"
    }
}
else {
    Write-Warning "Plan file '$PlanFile' kept for debugging because there were $($errors.Count) error(s)."
}

$result = @{
    created = $created.ToArray()
    errors  = $errors.ToArray()
}

Write-Output ($result | ConvertTo-Json -Depth 5)

if ($errors.Count -gt 0) {
    Write-Warning "$($errors.Count) ticket(s) failed — see the errors array in the output."
    exit 1
}
