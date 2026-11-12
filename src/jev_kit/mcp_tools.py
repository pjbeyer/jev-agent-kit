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
        # identity read: the connection's own account info (OBS 2026-11-11)
        "notion_personal-notion-get-self",
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
        # superblocks platform reads (OBS 2026-11-12, live via get_tool_schema:
        # audit-log fetch, app summary, deployment history — all read-only)
        "superblocks-get_audit_events",
        "superblocks-get_application_summary",
        "superblocks-get_application_deployment_history",
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

#: Provisioned catalog ids (jak-77q): the aggregator's canonical dispatch form
#: carries a server-assigned 32-hex `tool_id` that cannot be derived from the
#: target name (no hash construction matched; ids are assigned by the aggregator
#: at server-registration time). A *cached runtime* lookup would be server state
#: with stale-misclassification risk, but ids have proven stable across the full
#: 2026-11-10→11 shadow window (201 dispatches to the top id). So these entries
#: are PROVISIONED, each verified live through the aggregator
#: (`get_tool_schema(tool_id=...)`) on the marked date — the same evidence rule
#: as the name inventory above. Classification remains name-based: the id maps
#: only to a name, and the name still must exist in the per-server inventory
#: above; an id whose name is absent from the inventory fails closed exactly as
#: an unknown name. An id absent from this map fails closed as
#: `mcp_dispatch_target_id` in the parser — never blind.
TOOL_IDS: dict[str, str] = {
    # Verified live via get_tool_schema 2026-11-11 (OBS).
    "a1ca5a74ba5ff9eea51b378d98c14791": "slack-slack_read_channel",
    "eda3f9b6f661059347c6c54eb5043bf8": "slack-slack_read_thread",
    "883ba0404b04dee9f72f4f4259a29b74": "slack-slack_search_channels",
    "9cd0cba24732beaf23e5bf3c9b67f919": "notion_personal-notion-search",
    "ab98dadf00943b898e593d6772db1077": "notion_personal-notion-fetch",
    "6d4bc5df651c74e808ec75fcb50c86ee": "notion_personal-notion-query-data-sources",
    "d87c5d6e63f767e354026dd268391adf": "notion_personal-notion-get-self",
    "f3ae5871231c4b11eb8b4dccb14dc5fb": "notion_personal-notion-update-page",
    "b53929f48f4c714264aff5ebb9c34641": "flex-litellm-gateway-mcp_tool_search",
    "a26a54776da7d49225faf341ccf2e2fa": "flex-litellm-gateway-mcp_tool_call",
    # Verified live via get_tool_schema 2026-11-12 (OBS) — ids observed in the
    # live shadow log (32 rows) but absent from the 2026-11-11 provisioning.
    "adc9faf0db414a2cc297683a414e72a1": "slack-slack_search_public_and_private",
    "6a18c926e75cd28a56948741667e6b4a": "slack-slack_search_public",
    "8d011d97690530ee680cb8afa788147b": "notion_personal-notion-create-pages",
    "ef9e38db24eb913b36cea114a3faacf6": "notion_personal-notion-connector-search",
    "25c5c0b3781f74d07feb6e1ff13e4e4a": "slack-slack_send_message_draft",
    "2a5a3a24f0eb8e2a77466cdada0390c6": "notion_personal-notion-get-tool-access",
    "aef1b3392e9b8bd5b55fa40f155d3998": "superblocks-get_audit_events",
    "651d790c69ae5f7e5ea175cac28be4ad": "superblocks-get_application_summary",
    "9f9d9f4eaa4842e03da39c1668270019": "obscura-browser_get_attribute",
    "cddfe918379acec98e417668f965d578": "superblocks-get_application_deployment_history",
}


def classify(target: str) -> str:
    """The effect class of one dispatched target name, or "unknown".

    Accepts either the target NAME (``<server>-<tool>``, as the aggregator
    exposes it) or a provisioned catalog tool_id (jak-77q) — a tool_id maps to
    its name first, and only the name is classified. Pure and total: any string
    returns a class; an empty, unknown, or unprovisioned value returns
    "unknown" and the parser fails closed on it. Never raises.
    """
    if not target:
        return "unknown"
    target = TOOL_IDS.get(target, target)
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