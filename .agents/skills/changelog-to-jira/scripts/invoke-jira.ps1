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
# 3. DGW workflow
#    Backlog → To Do → Development → Reviewing → Done
#    Transitions are picked by the status they lead to, because their IDs
#    change whenever the workflow is edited. If the statuses change, the
#    error lists the transitions Jira offers; update this list from it.
# ---------------------------------------------------------------------------

$StatusChain = @("Backlog", "To Do", "Development", "Reviewing", "Done")

function Move-JiraIssueToDone {
    param([Parameter(Mandatory)] [string] $Key)

    # Each transition moves the issue at least one status forward, so this needs at most one step per status.
    for ($step = 0; $step -lt $StatusChain.Count; $step++) {
        $current = Get-JiraIssue -Key $Key
        $position = [array]::IndexOf($StatusChain, $current.Status)

        if ($position -eq $StatusChain.Count - 1) {
            return
        }

        # Take the transition that goes furthest along the chain, straight to Done when the workflow allows it.
        $next = $current.Transition |
            Where-Object { [array]::IndexOf($StatusChain, $_.ResultStatus.Name) -gt $position } |
            Sort-Object { [array]::IndexOf($StatusChain, $_.ResultStatus.Name) } -Descending |
            Select-Object -First 1

        if (-not $next) {
            $available = ($current.Transition | ForEach-Object { "$($_.Name) ($($_.ID)) → $($_.ResultStatus.Name)" }) -join ", "
            throw "no transition moves $Key forward from '$($current.Status)'; available: $available"
        }

        Invoke-JiraIssueTransition -Issue $Key -Transition $next
    }

    throw "$Key did not reach '$($StatusChain[-1])' after $($StatusChain.Count) transitions"
}

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
            # New-JiraIssue has no -Assignee parameter; -Fields entries go straight into the request body.
            $issueParams["Fields"] = @{ assignee = @{ accountId = $ticket.assignee_account_id } }
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

        # --- Walk the workflow to Done ---
        try {
            Move-JiraIssueToDone -Key $issue.Key
            Write-Host "  Transitioned $($issue.Key) to Done"
        } catch {
            Write-Warning "  Could not move $($issue.Key) to Done: $_"
            Write-Warning "  The ticket needs to be moved to Done manually."
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
