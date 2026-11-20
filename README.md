<div align="center">

# LumoAuth Guard for OpenClaw

**Check every tool call that your OpenClaw agent makes, before the tool runs.**<br>
Each call is allowed, sent to you for approval, or blocked, by rules that you keep in LumoAuth.

[![npm](https://img.shields.io/npm/v/@lumoauth/openclaw?style=flat-square&label=npm&color=111111)](https://www.npmjs.com/package/@lumoauth/openclaw)
[![CI](https://img.shields.io/github/actions/workflow/status/lumoauth/openclaw/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/lumoauth/openclaw/actions/workflows/ci.yml)
![OpenClaw 2026.11.5 or later](https://img.shields.io/badge/OpenClaw-2026.11.5%2B-111111?style=flat-square)
[![License: MIT](https://img.shields.io/badge/license-MIT-111111?style=flat-square)](LICENSE)

[Quick start](#quick-start) · [What it protects](#what-it-protects) · [Approvals](#approvals) · [Everyday commands](#everyday-commands) · [Troubleshooting](#troubleshooting) · [Documentation](https://docs.lumoauth.dev/agents/personal-agents)

</div>

---

Your OpenClaw agent reads files, runs commands, browses the web and sends messages for you.
To do that, it reads text that other people wrote: web pages, e-mails, documents and chat messages.
Any of that text can contain instructions that you never gave.

**LumoAuth Guard** is an OpenClaw plugin that checks each tool call before the tool runs.
The check happens in OpenClaw's own process, outside the model, so nothing that the model reads or writes can switch it off.
You keep the rules in LumoAuth, not in the conversation, so a prompt injection cannot change them.

```text
      Your agent wants to run a tool
                     │
                     ▼
   ┌──────────────────────────────────┐       ┌──────────────────────────┐
   │  LumoAuth Guard                  │ ◀──── │  LumoAuth                │
   │  inside OpenClaw, outside        │       │  · what the agent may do │
   │  the model                       │ ────▶ │  · approvals             │
   └──────────────────────────────────┘       │  · audit log             │
          │          │          │             └──────────────────────────┘
          ▼          ▼          ▼
       ✓ runs   ? asks you  ✗ blocked
```

## Why use it

- **Rules that you control.** You grant the agent capabilities such as `files:write`, `shell:exec` or `mcp:github:read:*`. A change in LumoAuth reaches the agent within a minute.
- **Approvals where you are.** A call that needs your approval goes to the LumoAuth app on your phone, to Slack or Discord, or to OpenClaw's own approval prompt.
- **Protected, whatever you grant.** The agent can never read the Guard's key, change OpenClaw's settings or open your credential stores.
- **Extra care after untrusted input.** After the agent reads a web page or an e-mail, actions that send data out need your approval.
- **A record of every decision.** Each decision becomes an entry in LumoAuth's audit log. Argument values stay on your machine.
- **Fails closed.** Every tool call is blocked until setup finishes. Calls are also blocked when LumoAuth cannot confirm the agent's permissions for longer than 5 minutes.

## Quick start

You need:

- OpenClaw 2026.11.5 or later.
- A LumoAuth organization. [Create one](https://app.lumoauth.dev/register) if you don't have one yet.

### 1. Install the plugin

```sh
openclaw plugins install npm:@lumoauth/openclaw
```

OpenClaw lists what the plugin registers and asks you to accept it.
From now until setup finishes, the Guard blocks every tool call. It fails closed on purpose.

### 2. Run setup

```sh
openclaw lumoauth setup
```

Setup asks for the address of your LumoAuth dashboard, for example `https://app.lumoauth.dev/orgs/acme/portal`.
It lists OpenClaw's tools and your MCP servers, and asks which [preset](#presets) to start from.
Then it creates a key for the agent and prints a link:

```text
Step 3 of 4  Create the agent's key
  ✓ Key saved to /home/you/.lumoauth/guard/openclaw/agent-key.pem (only your user can read it; it never leaves this machine)
    Key fingerprint: Hc4T-9wQe-Lm2P-x7Ra

Step 4 of 4  Approve the agent in LumoAuth
  Open this page, sign in, and approve:
    https://app.lumoauth.dev/orgs/acme/portal/agents/enroll?code=KQPM-WTRD
  Check that the page shows code KQPM-WTRD and key fingerprint Hc4T-9wQe-Lm2P-x7Ra.
  Approve only if you ran this command yourself just now.
  … waiting for approval (15 min left)
```

### 3. Approve the agent in LumoAuth

Open the link and sign in. Check that the page shows the same code and key fingerprint as your terminal.
The page lists the capabilities that the preset ticked. Change the ticks if you like, then approve.

> **Approve only an agent that you set up yourself, just now.**
> If someone sends you a code or a link, deny it. Approving it would give their machine access to your organization in your name.

Setup then continues on its own. It saves its settings, turns the plugin on, runs a self-test and lists what the agent may do without asking:

```text
Self-test
  ✓ Token (private_key_jwt + DPoP) and capability snapshot: agent active
  ✓ Audit receipt delivered (tool lumoauth.selftest)

Granted without asking (19)
  • files:read Read files
  • files:write Create and change files
  • web:search Search the web
  • web:fetch Open web pages
  …
  Everything else asks you first. The Guard always protects its key, OpenClaw's configuration and your credential stores.
```

### 4. Restart the gateway

If an OpenClaw gateway is running, restart it once so that it loads the Guard:

```sh
openclaw gateway restart
```

### Try it

Ask your agent to show you `~/.ssh/id_rsa`. The Guard blocks the call, and the model gets the reason:

```text
LumoAuth Guard blocked this call. Protected by a rule that cannot be changed: a credential store (SSH, cloud, registry or browser secrets). Do not try another way to do this.
```

Then run `openclaw lumoauth status`. It shows the agent, its capabilities, the connection to LumoAuth and the latest decisions.

<details>
<summary><b>Set up without questions, for scripts</b></summary>

<br>

```sh
openclaw plugins install npm:@lumoauth/openclaw --accept-capabilities
openclaw lumoauth setup --url https://app.lumoauth.dev/orgs/acme/portal --preset assistant --approvals auto --yes
```

A script cannot answer the install question, so it needs `--accept-capabilities`.
You still approve the agent in LumoAuth: setup prints the link and waits for you.

</details>

## What it protects

| Area | What the Guard does |
|---|---|
| **Every tool call** | Checks built-in tools, MCP tools and plugin tools before they run. Each call is allowed, sent to you for approval, or blocked. |
| **Its own integrity** | The agent cannot read the Guard's key, change OpenClaw's or the Guard's settings, install or remove plugins, or run `openclaw plugins`, `openclaw config` or `openclaw lumoauth`. No setting, capability or approval removes these rules. |
| **Secrets on disk** | SSH keys, cloud credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`), package registry tokens, browser profiles and OpenClaw's credential store are blocked. `.env` files, `*.pem` and `*.key` files need your approval. The same rules apply to paths that MCP and plugin tools receive, such as a filesystem MCP server. |
| **Persistence** | Writing to shell start-up files (`~/.bashrc`, `~/.zshrc`), autostart entries, systemd user units and LaunchAgents needs your approval. So do crontab edits and `at` jobs. |
| **Untrusted input** | Some tools bring in text that other people wrote: web pages, search results, PDFs, images and messages. After such a tool runs, actions that send data out need your approval for 30 minutes, even when they are granted. |
| **Memory and skills** | While the session holds untrusted input, writing standing instructions needs approval. Creating or changing a skill always needs approval. File tools may read the skills in OpenClaw's state directory, but never change them. |
| **Identity** | The agent signs in to LumoAuth with its own key pair (`private_key_jwt`) and sender-constrained tokens (DPoP). There is no shared secret. |
| **Stop switch** | Suspend or delete the agent in LumoAuth, and every tool call stops within a minute. On the machine, `openclaw lumoauth lock` stops them at once. |
| **Audit** | Every decision becomes an entry in LumoAuth's audit log. Argument values never leave the machine; only a SHA-256 digest is sent. |
| **OpenClaw's own settings** | `openclaw lumoauth doctor` checks the sandbox, who may message the agent, an exposed gateway, file permissions and plaintext secrets, and says what to change. |

## How a call is checked

The Guard takes these steps for every call. The first step that applies gives the answer.

1. **Locked?** Blocked until you run `openclaw lumoauth unlock`.
2. **Not set up?** Blocked.
3. **Protected?** A call that touches the Guard, OpenClaw's configuration or a credential store is blocked. A call that touches a `.env` file or a start-up file asks you first.
4. **No confirmation from LumoAuth?** The call is blocked when the agent is suspended. It is also blocked when LumoAuth cannot confirm the agent's permissions for longer than the offline grace (5 minutes by default).
5. **Granted?** The call runs, unless the session took in untrusted input and the call can send data out. Then it asks you.
6. **Not granted?** It asks you. You can set it to block instead.

Each tool call maps to one capability:

| Kind of tool | Capability | Example |
|---|---|---|
| Built-in tools | A fixed capability for each tool | `read` is `files:read`, `exec` is `shell:exec`, `message` is `messages:send` |
| MCP tools | `mcp:<server>:<risk>:<tool>` | `mcp:github:read:list_issues`. Grant `mcp:github:read:*` to allow every read-only GitHub tool. |
| Other plugin tools | `tool:<name>` | `tool:weather` |
| `dispatch_action` | The capability of the tool that it runs | A `web_fetch` through `dispatch_action` is checked as `web_fetch`, with its own arguments. The Guard asks at most once. |

The risk of an MCP tool comes from the tool's name.
When a call is blocked, the model receives the reason.
If a capability is missing, the message tells the owner which one to add, with a link to the agent's page in LumoAuth.

## Presets

Setup sends LumoAuth a checklist of capabilities. The preset sets which boxes start ticked.
You can change the ticks on the approval page, and later in LumoAuth.

| Preset | Allowed without asking |
|---|---|
| `observer` | Reading files, web search and pages, memory, sessions, media and skills. The read-only tools of each MCP server. |
| `assistant` (default) | Everything in `observer`, plus writing files and memory, goals and tasks, widgets, and generating media. The read and write tools of each MCP server. |
| `builder` | Everything in `assistant`, plus shell commands, code, background processes, sub-agents and the browser. |

No preset ticks sending messages, scheduled jobs, device control, stored secrets, host administration or skill changes.
You grant those on purpose.

## Approvals

When a call needs approval, the Guard asks a person. The `approvals` setting chooses where:

| Setting | Where you approve |
|---|---|
| `auto` (default) | Through LumoAuth, when the agent may act on your behalf. Otherwise, or when LumoAuth cannot reach you, in OpenClaw. |
| `lumoauth` | Only through LumoAuth. |
| `host` | In OpenClaw: the Control UI and chat channels that support approvals. |
| `off` | Nowhere: every call that needs approval is blocked. |

### On your phone, in Slack or in Discord

LumoAuth sends each request to the LumoAuth app on the owner's phone and to your organization's Slack and Discord approval channels.
Only the agent's owner can answer, and the first answer counts.
While a call waits, `openclaw lumoauth status` says where you can answer it.

LumoAuth approvals need the agent's **Can act on behalf of users** switch in LumoAuth.
This switch and the approval channels are part of the Agent Governance add-on.
Set up the channels in LumoAuth under **Integrations → Approval channels**.

### In OpenClaw

Approvals in OpenClaw work on every LumoAuth plan.
You can answer **Allow once**, **Allow always** or **Deny**.

- **Allow always** is offered only for a capability that the agent was not granted. It lasts for the current session and capability, and ends when OpenClaw restarts.
- Calls that touch something protected, and calls after untrusted input, ask every time.
- Runs with no one to answer, such as cron jobs, heartbeats and `openclaw agent` from a script, cannot show an approval. OpenClaw blocks those calls. Grant the capability in LumoAuth if the run needs it.

### What a request shows

Every request shows the tool, the reason, the capability, the risk and up to five arguments.
Values of arguments named like passwords, tokens, keys or cookies are hidden.

```text
Allow send_email on gmail?
Why: After the agent read untrusted content
Capability: mcp:gmail:external:send_email
Risk: external
body: Hi Alex, here are the numbers that you asked for.
subject: Q3 report
to: alex@example.com
```

## Everyday commands

| What you want | Command |
|---|---|
| See the agent, its capabilities, the connection and recent decisions | `openclaw lumoauth status` |
| Check the Guard and OpenClaw's security settings | `openclaw lumoauth doctor` |
| Stop every tool call on this machine, at once | `openclaw lumoauth lock [reason]` |
| Let tool calls run again | `openclaw lumoauth unlock` |
| Enroll a new agent in place of the current one | `openclaw lumoauth setup --force` |
| Delete the key and the settings on this machine | `openclaw lumoauth reset` |

In a chat, the owner can send `/lumoauth` for a short status and `/lumoauth lock` to stop every tool call.
Unlocking works only in a terminal.

<details>
<summary><b>All options</b></summary>

<br>

| Command | Options |
|---|---|
| `setup` | `--url <dashboard address>`, or `--region us\|eu` with `--org <organization>` · `--preset observer\|assistant\|builder` · `--approvals auto\|lumoauth\|host\|off` · `--name <agent name>` · `--yes` asks no questions · `--force` enrolls a new agent even when one is set up |
| `status` | `--json` prints JSON · `--offline` skips LumoAuth |
| `doctor` | `--json` prints JSON · `--offline` skips LumoAuth. It changes nothing. |
| `lock [reason]` | The reason appears in `status`. |
| `reset` | `--yes` skips the question. The agent stays in LumoAuth until you delete it there. |

</details>

`openclaw security audit` does not show the Guard's checks: OpenClaw 2026.11.5 loads plugins there without running them.
Use `openclaw lumoauth doctor` instead.

The plugin includes the skill `lumoauth-guard`.
The skill tells the model what to do when a call waits for approval or is blocked.

## Configuration

The Guard keeps its files in `~/.lumoauth/guard/openclaw/`. Set `LUMOAUTH_GUARD_HOME` to use another directory.
The directory is readable only by your user (mode `0700`, files `0600`), and the agent cannot read or change it.

<details>
<summary><b>Files</b></summary>

<br>

| File | Content |
|---|---|
| `config.json` | Settings (below). |
| `agent-key.pem` | The agent's private key (EC P-256). |
| `lock` | Present while the lock is on. |
| `status.json` | The last report of the running OpenClaw process, for `status`. |
| `receipts-queue.jsonl` | Audit receipts that were not delivered before OpenClaw exited. They are sent on the next start. |

</details>

<details>
<summary><b>Settings in <code>config.json</code></b></summary>

<br>

| Key | Default | Meaning |
|---|---|---|
| `approvals` | `auto` | Where a person approves: `auto`, `lumoauth`, `host` or `off`. |
| `onUngranted` | `ask` | A call without a granted capability asks (`ask`) or is blocked (`block`). |
| `decisionMode` | `local` | `local` checks capabilities on this machine and works on every plan. `server` asks LumoAuth's Ask API for each call. |
| `taint.enabled` | `true` | Ask before sending data out after untrusted input. |
| `taint.windowSeconds` | `1800` | How long a session counts as holding untrusted input. |
| `taint.escalate` | `["external"]` | Risks that need approval after untrusted input. The strict choice is `["external", "execute", "egress"]`. |
| `refreshSeconds` | `60` | How often the Guard reloads the agent's capabilities (30 to 600). |
| `offlineGraceSeconds` | `300` | How long the last capabilities stay valid while LumoAuth cannot be reached (0 to 3600). |
| `receipts` | `true` | Send an audit receipt for each decision. |
| `rememberApprovals` | `true` | Offer and honour **Allow always** for capabilities that are not granted, for the session. |
| `extraProtectedPaths` | `[]` | More paths that the agent may never read or write. |
| `allowPaths` | `[]` | Parts of OpenClaw's state directory that the agent may use. This never opens the Guard's files, OpenClaw's configuration or credential stores. |

A value out of range falls back to its default, and `status` reports it.
The Guard reads `config.json` again when it changes.

</details>

## Limits

The Guard is strong, but it is not a sandbox. Please read these limits.

- **It runs inside OpenClaw's process.** An agent that may run shell commands or code runs them as your user. The Guard scans each command for protected paths and dangerous patterns, but a scan is a tripwire, not a sandbox. Combine the Guard with OpenClaw's sandbox (`agents.defaults.sandbox.mode`), which `doctor` recommends.
- **Only the tool hook is checked.** The Guard checks the calls that OpenClaw sends through its tool hook. In OpenClaw 2026.11.5 no other path is known.
- **MCP risk comes from tool names.** A malicious MCP server can give a tool a harmless name. Its calls still follow the rules for untrusted input and approvals.
- **Some state is kept in memory.** Taint and **Allow always** end when OpenClaw restarts.
- **Other plugins run first.** Plugins that run before the Guard can change a call's arguments. The Guard runs last, so it checks the arguments that the tool really gets. A plugin that blocks a call ends the check before the Guard runs.

## Troubleshooting

| What you see | What to do |
|---|---|
| Every call is blocked with "LumoAuth Guard is not set up" | Run `openclaw lumoauth setup`. If you ran `reset`, run setup again. |
| "LumoAuth cannot confirm this agent's permissions" | Run `openclaw lumoauth status`. It shows whether LumoAuth can be reached and whether it still accepts the agent's key. If the agent or its key was deleted in LumoAuth, run `openclaw lumoauth reset --yes` and then `setup`. |
| A TLS error, when LumoAuth uses a private certificate | Start OpenClaw with `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`, or with Node's `--use-system-ca`. The Guard has no switch to turn off certificate checks. |
| An approval in the LumoAuth app times out | OpenClaw ends a hook after its timeout. Setup sets `plugins.entries.lumoauth.hooks.timeouts.before_tool_call` to `180000` when LumoAuth approvals are on. `doctor` checks it. |
| "Plugin approval unavailable" in a script or cron job | These runs have no one to answer. Grant the capability in LumoAuth, or run the task from a chat or the Control UI. |
| OpenClaw cannot verify where the plugin came from | OpenClaw shows this for plugins that are not installed from ClawHub. Install from npm with `npm:@lumoauth/openclaw`. To load only the plugins that you chose, list them in `plugins.allow`. |

## Uninstall

```sh
openclaw lumoauth reset --yes
openclaw plugins uninstall lumoauth
```

Then delete the agent in LumoAuth. `reset` prints the link to its page.

## Development

```sh
npm install
npm run build          # TypeScript → dist/
npm test               # node --test: contract vectors, client, hooks, CLI
npm run sync-contract  # copy catalog, vectors and skill from ../agent-guard
```

To try the plugin in a real OpenClaw against a real LumoAuth, run `CA_CERT=/path/to/root.crt e2e/start.sh`.
It needs Docker; the comments at the top of the script explain the options.

The behaviour follows the [LumoAuth Guard contract](https://github.com/lumoauth/agent-guard) (`SPEC.md` in the `agent-guard` repository).
The catalog, the test vectors and the skill are copied into `contract/` and `skills/`.
A test fails when the copy differs from `../agent-guard`.
The package has no runtime dependencies.

## See also

- [LumoAuth Guard for Hermes Agent](https://github.com/lumoauth/hermes): the same protection for Hermes.
- [Secure OpenClaw and Hermes agents](https://docs.lumoauth.dev/agents/personal-agents): the guide in the LumoAuth documentation.
- [LumoAuth Guard contract](https://github.com/lumoauth/agent-guard): the open specification and the test cases that this plugin passes.

## License

MIT. See [LICENSE](LICENSE).
