# Changelog

## 0.1.0 (unreleased)

First release of LumoAuth Guard for OpenClaw (plugin id `lumoauth`), built to the LumoAuth Guard contract v1.

- Checks every tool call in a `before_tool_call` hook at priority -1000: allowed, sent for approval, or blocked.
- Hard rules that no setting removes: the Guard's files, OpenClaw's configuration and credentials, plugin management, OpenClaw's admin commands, credential stores and browser profiles. Approval for `.env`, key files, start-up files, crontab and `at`.
- Calls through `dispatch_action` are checked as the tool that they run (tool-search ids included), with one decision and one receipt per call.
- Path checks for absolute and home paths in any argument of MCP and plugin tools; installed skills are readable but not writable.
- Shell and code scanning: path tokens (with symlinks resolved), protected paths inside strings, admin commands, package changes to OpenClaw or the Guard, stopping OpenClaw, and protected environment variables.
- Capabilities from LumoAuth (`local` mode) or the Ask API (`server` mode), with an offline grace.
- Taint: after untrusted input, actions that send data out need approval; so does writing standing instructions.
- Approvals in the LumoAuth app (push) or in OpenClaw (`requireApproval`). **Allow always** is offered only for capabilities that are not granted, and kept per session and capability.
- Audit receipts for every decision (`after_tool_call` completes them), batched, with back-off, and kept on disk when OpenClaw exits before delivery.
- `openclaw lumoauth setup | status | doctor | lock | unlock | reset` and the `/lumoauth` chat command. Doctor findings are also registered as a security-audit collector.
- The `lumoauth-guard` skill.
- No runtime dependencies. Node 24 or later.
