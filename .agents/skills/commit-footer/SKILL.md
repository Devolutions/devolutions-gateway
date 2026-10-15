---
name: commit-footer
description: Write the trailing footers of a commit message or pull request body in the Devolutions Gateway repository. Use whenever adding an Issue, Changelog, or Security footer, linking a Jira ticket or GitHub issue from a commit, or deciding how to reference the work item behind a change.
---

# Devolutions Gateway commit footers

`cliff.toml` turns every `Issue:` footer value into a Jira link, `https://devolutions.atlassian.net/browse/<value>`, in the changelog.
Put only a bare Jira key there, one footer per ticket: `Issue: DGW-123`, `Issue: DVLS-14057`.
A GitHub issue or pull request number (`#1993`, `Devolutions/IronRDP#1505`), a URL, a Markdown link, or `N/A` produces a broken link; never write them in an `Issue:` footer, and omit the footer when there is no Jira ticket.
Reference a GitHub issue in the body with a closing keyword instead, such as `Fixes #2070`; GitHub closes it on merge and git-cliff ignores it.

Add `Changelog: ignore` to keep an otherwise included commit out of the changelog.
Add `Security: yes` to list the commit under the Security section.
