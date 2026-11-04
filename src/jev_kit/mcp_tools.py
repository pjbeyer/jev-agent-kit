"""MCP dispatch-target semantics for the local property parser (jak-b8n).

The Hermes `mcp__local_mcp_aggregator__call_tool` bridge dispatches a tool on a
configured MCP server. The bridge itself has no effect of its own — its effect
is the effect of the dispatched target, which varies per server. This module is
the per-server inventory: it classifies each KNOWN dispatch target into the
same effect classes `hermes_tools` uses, from evidence, not guesses.

Evidence rule (owner direction: classify from `get_tool_schema` output and the
server's actual behavior, NOT guesses). Every entry below was classified from
the tool's own schema/description text observed live through the aggregator on
2026-11-04 (marked OBS), or from the behavior a parent schema explicitly
documents for it (marked REF — e.g. `slack_send_message`'s description names
`slack_search_channels` and describes it as a channel-ID lookup). Anything
neither observed nor referenced is absent from this module and fails closed
(`mcp_dispatch_target_unknown`): a newly installed server or a renamed tool
asks, with no registry change needed.

Effect classes mirror hermes_tools:

- READERS: the target only reads/searches/lists from its remote service. The
  call still egresses (every aggregator call goes over the local proxy), so the
  parser fires `network_upload` for it — a TRUE statement — and stays
  confident so the calibrated questions judge the egress.
- WRITERS: the target mutates remote state (send/post/create/update/install).
  The vocabulary has no remote-mutation property, so these stay UNCONFIDENT
  (`remote_state_write`): a blind remote write must never parse confidently,
  the same rule as blind local writes.
- CODE_EXEC: the target executes code/payload the parser cannot see
  (`runs_unseen_code`, same rule as interpreters).
- AUTHORITY: the target mints standing or delegated authority (pre-signed
  URLs): unconfident (`mcp_grants_authority`).
"""

from __future__ import annotations

#: Dispatch-target classes. Keys are the dispatched tool `name` values exactly
#: as the aggregator exposes them ("<server>-<tool>").
READERS: frozenset[str] = frozenset(
    {
        # slack (OBS for search_public, search_public_and_private, read_channel;
        # REF for the rest, named and described in those schemas)
        "slack-slack_search_public",
        "slack-slack_search_public_and_private",
        "slack-slack_read_channel",
        "slack-slack_read_thread",
        "slack-slack_read_canvas",
        "slack-slack_search_channels",
        "slack-slack_search_users",
        # notion (OBS for fetch, search, connector-search, get-tool-access,
        # calendar-list-calendar-resources; REF for the rest)
        "notion_personal-notion-fetch",
        "notion_personal-notion-search",
        "notion_personal-notion-connector-search",
        "notion_personal-notion-get-tool-access",
        "notion_personal-notion-get-comments",
        "notion_personal-notion-get-file-download-urls",
        "notion_personal-notion-query-data-sources",
        "notion_personal-notion-ai-search",
        "notion_personal-notion-calendar-list-calendar-resources",
        # aws docs/metadata (OBS)
        "aws_mcp-aws___search_documentation",
        "aws_mcp-aws___read_documentation",
        "aws_mcp-aws___get_regional_availability",
        "aws_mcp-aws___retrieve_skill",
        "aws_mcp-aws___list_regions",
        # superblocks Security Center reads (OBS)
        "superblocks-list_dependency_scan_findings",
        "superblocks-get_dependency_scan_summary",
        "superblocks-list_cve_exceptions",
        # dryrun_security reports (OBS)
        "dryrun_security-get_security_report",
        "dryrun_security-get_pr_insight",
        # homebrew reads (OBS)
        "homebrew-list",
        "homebrew-info",
        "homebrew-doctor",
        # flex-litellm-gateway discovery (OBS)
        "flex-litellm-gateway-mcp_tool_search",
        "flex-litellm-gateway-agent_search",
        # obscura-browser page reads (OBS)
        "obscura-browser_snapshot",
        "obscura-browser_links",
        "obscura-browser_interactive_elements",
        "obscura-browser_get_attribute",
    }
)

WRITERS: frozenset[str] = frozenset(
    {
        # slack remote-state writes (OBS for send_message, send_message_draft,
        # schedule_message, update_canvas; REF create_canvas)
        "slack-slack_send_message",
        "slack-slack_send_message_draft",
        "slack-slack_schedule_message",
        "slack-slack_update_canvas",
        "slack-slack_create_canvas",
        # notion writes (OBS for create-pages, update-page, create-database,
        # create-view, create-attachment, upload-skill, create-file-upload;
        # REF create-comment, create-meeting-note, update-data-source)
        "notion_personal-notion-create-pages",
        "notion_personal-notion-update-page",
        "notion_personal-notion-create-database",
        "notion_personal-notion-create-view",
        "notion_personal-notion-create-comment",
        "notion_personal-notion-create-meeting-note",
        "notion_personal-notion-update-data-source",
        "notion_personal-notion-create-attachment",
        "notion_personal-notion-upload-skill",
        "notion_personal-notion-create-file-upload",
        # homebrew package changes (OBS)
        "homebrew-install",
        "homebrew-uninstall",
        "homebrew-upgrade",
    }
)

CODE_EXEC: frozenset[str] = frozenset(
    {
        # aws: arbitrary Python against boto3 — script body is payload, calls
        # can mutate AWS resources (OBS).
        "aws_mcp-aws___run_script",
        # obscura-browser page-side effects: JS evaluation and element
        # interaction act on whatever site is loaded — arbitrary effect (OBS).
        "obscura-browser_evaluate",
        "obscura-browser_click",
        "obscura-browser_type",
        # browser navigation that leaves the read-only path: a POST-form
        # submit or login flow via click/type is covered above; a bare
        # navigate() is classified in NAVIGATORS instead.
    }
)

#: Navigation: fetches a URL into the browser (a GET-shaped download of the
#: page) without executing page-side effects. network_download is the TRUE
#: fact; confident so the questions judge it.
NAVIGATORS: frozenset[str] = frozenset(
    {
        "obscura-browser_navigate",
    }
)

#: Targets that mint delegated authority rather than mutate state (OBS:
#: aws get_presigned_url — the returned URL IS an upload/download grant).
AUTHORITY: frozenset[str] = frozenset(
    {
        "aws_mcp-aws___get_presigned_url",
    }
)

_KNOWN = READERS | WRITERS | CODE_EXEC | NAVIGATORS | AUTHORITY


def classify(target: str) -> str:
    """The effect class of one dispatched target name, or "unknown".

    Pure and total: any string returns a class; an empty or unknown name
    returns "unknown" and the parser fails closed on it. Never raises.
    """
    if not target:
        return "unknown"
    if target in READERS:
        return "reader"
    if target in WRITERS:
        return "writer"
    if target in CODE_EXEC:
        return "code_exec"
    if target in NAVIGATORS:
        return "navigator"
    if target in AUTHORITY:
        return "authority"
    return "unknown"