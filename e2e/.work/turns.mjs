#!/usr/bin/env node
// End-to-end stage 2: scripted agent turns through a real OpenClaw gateway in
// the e2e container (set up by e2e/start.sh and approved in LumoAuth), with
// the mock model choosing the tool calls. Prints tool → expected → actual,
// then `openclaw lumoauth status --json` and `doctor --json`, and waits for
// the receipts to be delivered.
//
//   node e2e/turns.mjs
//
// Environment: CONTAINER (default lumoauth-oc-e2e), GATEWAY_PORT (28789),
// GATEWAY_LOG_LEVEL (e.g. debug, when the script starts the gateway),
// APPROVALS (default host: approvals end in OpenClaw's non-interactive
// refusal instead of a push or an e-mail to the approver; "keep" leaves the
// setting as it is).
import { execFileSync, spawnSync } from 'node:child_process';

const CONTAINER = process.env.CONTAINER ?? 'lumoauth-oc-e2e';
const PORT = process.env.GATEWAY_PORT ?? '28789';
const APPROVALS = process.env.APPROVALS ?? 'host';
const TOKEN = 'e2e-gateway-token';
const ENV = `NODE_EXTRA_CA_CERTS=/e2e/ca.crt OPENCLAW_GATEWAY_TOKEN=${TOKEN}`;

function sh(script, { allowFail = false, input } = {}) {
  const r = spawnSync('docker', ['exec', '-i', CONTAINER, 'bash', '-c', script], { encoding: 'utf8', input, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0 && !allowFail) throw new Error(`docker exec failed (${r.status}): ${r.stderr || r.stdout}`);
  return r.stdout;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Scenarios. `expect` per tool call: ran, blocked, approval (asked, then refused
// because the run has no one to answer).
// OpenClaw 2026.11.5 offers these tools directly in this setup: apply_patch,
// dispatch_action, edit, exec, github_publish, ls, message, openclaw, process,
// read, sessions_yield, tool_describe, tool_search, write. Every other tool
// (web_fetch, memory, ...) is reached through dispatch_action {id, args}.
const SCENARIOS = [
  { label: 'read a workspace file', calls: [{ name: 'read', arguments: { path: 'notes.md' } }], expect: ['ran'] },
  { label: 'write a workspace file (files:write granted)', calls: [{ name: 'write', arguments: { path: 'out.md', content: 'x' } }], expect: ['ran'] },
  {
    label: 'dispatch_action → web_fetch (web:fetch granted; taints the session)',
    calls: [{ name: 'dispatch_action', arguments: { id: 'web_fetch', args: { url: 'https://example.com/' } } }],
    expect: ['ran'],
  },
  {
    label: 'dispatch_action → personal_instructions, clean session (memory:write granted)',
    calls: [{ name: 'dispatch_action', arguments: { id: 'personal_instructions', args: { action: 'view' } } }],
    expect: ['ran'],
  },
  {
    label: 'dispatch_action → web_fetch, then → personal_instructions (tainted)',
    calls: [
      { name: 'dispatch_action', arguments: { id: 'web_fetch', args: { url: 'https://example.com/' } } },
      { name: 'dispatch_action', arguments: { id: 'personal_instructions', args: { action: 'view' } } },
    ],
    expect: ['ran', 'approval'],
  },
  { label: 'send a message (messages:send not granted)', calls: [{ name: 'message', arguments: { action: 'send', to: 'someone', message: 'hi' } }], expect: ['approval'] },
  { label: 'read ~/.ssh/id_rsa', calls: [{ name: 'read', arguments: { path: '~/.ssh/id_rsa' } }], expect: ['blocked'] },
  { label: 'read the Guard key', calls: [{ name: 'read', arguments: { path: '/root/.lumoauth/guard/openclaw/agent-key.pem' } }], expect: ['blocked'] },
  { label: 'exec cat openclaw.json', calls: [{ name: 'exec', arguments: { command: 'cat ~/.openclaw/openclaw.json' } }], expect: ['blocked'] },
  { label: 'exec openclaw plugins disable lumoauth', calls: [{ name: 'exec', arguments: { command: 'openclaw plugins disable lumoauth' } }], expect: ['blocked'] },
  { label: 'exec ls (shell:exec not granted)', calls: [{ name: 'exec', arguments: { command: 'ls' } }], expect: ['approval'] },
  { label: 'write an installed skill', calls: [{ name: 'write', arguments: { path: '/root/.openclaw/skills/evil/SKILL.md', content: 'x' } }], expect: ['blocked'] },
  {
    label: 'apply_patch to openclaw.json',
    calls: [{ name: 'apply_patch', arguments: { input: '*** Begin Patch\n*** Update File: /root/.openclaw/openclaw.json\n@@\n-a\n+b\n*** End Patch' } }],
    expect: ['blocked'],
  },
  { label: 'edit ~/.bashrc (persistence)', calls: [{ name: 'edit', arguments: { path: '~/.bashrc', oldText: 'a', newText: 'b' } }], expect: ['approval'] },
  { label: 'openclaw tool (host admin)', calls: [{ name: 'openclaw', arguments: { message: 'show the gateway status' } }], expect: ['approval'] },
  { label: 'two calls: read, then read ~/.aws/credentials', calls: [{ name: 'read', arguments: { path: 'notes.md' } }, { name: 'read', arguments: { path: '~/.aws/credentials' } }], expect: ['ran', 'blocked'] },
  { label: 'MCP-style name with no such server', calls: [{ name: 'filesystem__read_file', arguments: { path: '~/.ssh/id_rsa' } }], expect: ['not offered'] },
];

function classify(result) {
  if (result === undefined) return { kind: 'no result', detail: '' };
  if (/LumoAuth Guard blocked this call\./.test(result)) {
    return { kind: 'blocked', detail: result.replace(/^.*LumoAuth Guard blocked this call\.\s*/s, '').replace(/"\s*}?\s*$/, '').slice(0, 90) };
  }
  if (/Plugin approval (unavailable|required)|approval-capable/.test(result)) {
    return { kind: 'approval', detail: (/Plugin approval [^"\n]*/.exec(result)?.[0] ?? 'approval').slice(0, 90) };
  }
  if (/not found|unknown tool|not available|is not allowed/i.test(result)) return { kind: 'not offered', detail: 'OpenClaw rejects it before plugin hooks' };
  return { kind: 'ran', detail: result.replace(/\s+/g, ' ').slice(0, 60) };
}

function toolResults(text) {
  const out = [];
  const re = /TOOL RESULT\[(\d+)\] >>> ([\s\S]*?)(?=\nTOOL RESULT\[\d+\] >>> |$)/g;
  let m;
  while ((m = re.exec(text))) out[Number(m[1]) - 1] = m[2];
  return out;
}

async function ensureGateway() {
  if (sh(`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/ || true`, { allowFail: true }).trim().match(/^[1-5]\d\d$/)) return;
  sh(`openclaw config set gateway.mode local >/dev/null && openclaw config set gateway.port ${PORT} >/dev/null`);
  execFileSync('docker', ['exec', '-d', CONTAINER, 'bash', '-c', `cd /root && ${ENV} openclaw gateway run --bind loopback --port ${PORT} ${process.env.GATEWAY_LOG_LEVEL ? `--log-level ${process.env.GATEWAY_LOG_LEVEL}` : ''} > /tmp/e2e-gateway.log 2>&1`]);
  for (let i = 0; i < 120; i++) {
    if (/http server listening/.test(sh('cat /tmp/e2e-gateway.log 2>/dev/null || true', { allowFail: true }))) return;
    await sleep(1000);
  }
  throw new Error('the gateway did not start; see /tmp/e2e-gateway.log in the container');
}

async function main() {
  if (APPROVALS !== 'keep') {
    sh(`node -e '
      const fs = require("fs"); const p = "/root/.lumoauth/guard/openclaw/config.json";
      const c = JSON.parse(fs.readFileSync(p, "utf8")); c.approvals = process.argv[1];
      fs.writeFileSync(p + ".tmp", JSON.stringify(c, null, 2), { mode: 0o600 }); fs.renameSync(p + ".tmp", p);' ${APPROVALS}`);
  }
  sh(`mkdir -p /root/.openclaw/workspace && echo "hello from the workspace" > /root/.openclaw/workspace/notes.md`);
  console.log(`› Gateway on 127.0.0.1:${PORT} (approvals: ${APPROVALS})`);
  await ensureGateway();

  const rows = [];
  let n = 0;
  for (const s of SCENARIOS) {
    n++;
    sh('cat > /tmp/e2e-tool-call.json', { input: JSON.stringify(s.calls) });
    const raw = sh(`cd /root && ${ENV} timeout 280 openclaw agent --agent main --session-id e2e-${Date.now()}-${n} --message "turn ${n}" --json 2>/tmp/e2e-turn.err`, { allowFail: true });
    let final = '';
    try {
      const j = JSON.parse(raw);
      const r = j.result ?? j;
      final = r.meta?.finalAssistantMessageRawText ?? r.finalAssistantMessageRawText ?? JSON.stringify(r);
    } catch {
      final = raw;
    }
    const results = toolResults(final);
    // OpenClaw rejects a tool that it does not offer before any plugin hook runs.
    if (results.length === 0 && /unknown tool/i.test(final)) s.calls.forEach((_, i) => (results[i] = 'unknown tool'));
    s.calls.forEach((call, i) => {
      const actual = classify(results[i]);
      rows.push({ scenario: s.label, tool: call.name, expected: s.expect[i], actual: actual.kind, ok: actual.kind === s.expect[i], detail: actual.detail });
    });
  }

  console.log('\n| # | Scenario | Tool | Expected | Actual | OK | Detail |');
  console.log('|---|---|---|---|---|---|---|');
  rows.forEach((r, i) => console.log(`| ${i + 1} | ${r.scenario} | \`${r.tool}\` | ${r.expected} | ${r.actual} | ${r.ok ? '✓' : '✗'} | ${r.detail.replace(/\|/g, '\\|')} |`));

  console.log('\n› openclaw lumoauth status --json');
  console.log(sh(`cd /root && ${ENV} openclaw lumoauth status --json 2>/dev/null`, { allowFail: true }));
  console.log('› openclaw lumoauth doctor --json');
  console.log(sh(`cd /root && ${ENV} openclaw lumoauth doctor --json 2>/dev/null`, { allowFail: true }));

  console.log('› Waiting 12 s for receipts to be delivered');
  await sleep(12_000);
  const status = JSON.parse(sh('cat /root/.lumoauth/guard/openclaw/status.json'));
  console.log(JSON.stringify({ receipts: status.receipts, lastError: status.lastError, recent: status.recent }, null, 2));
  process.exitCode = rows.every((r) => r.ok) ? 0 : 1;
}

main().catch((err) => {
  console.error(`✗ ${err.message}`);
  process.exitCode = 1;
});
