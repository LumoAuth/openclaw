// CLI commands end to end against the mock LumoAuth (non-interactive).
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, afterEach, before, beforeEach, describe, test } from 'node:test';
import {
  capabilityChecklist,
  doctorCommand,
  lockCommand,
  parseDashboardUrl,
  resetCommand,
  setupCommand,
  statusCommand,
  unlockCommand,
  type CommandDeps,
} from '../src/cli/commands.ts';
import { registerLumoauthCli } from '../src/cli/register.ts';
import { resolveHostPaths } from '../src/host/host-env.ts';
import { keyFingerprint } from '../src/lumoauth/crypto.ts';
import { MockLumoAuth, ORIGIN } from './helpers/mock-lumoauth.ts';
import { captureIo, fakeMachine, noSleep, setUpGuard } from './helpers/fixtures.ts';

let mock: MockLumoAuth;
let m: ReturnType<typeof fakeMachine>;
before(async () => {
  mock = await new MockLumoAuth().start();
});
after(async () => {
  await mock.stop();
});
beforeEach(() => {
  m = fakeMachine();
  mock.enrollmentPoll = [];
  mock.enrollmentStartReply = undefined;
  mock.enrollmentFingerprint = undefined;
});
afterEach(() => m.cleanup());

function deps(overrides: Partial<CommandDeps> = {}, hostConfig: any = {}): CommandDeps & { io: ReturnType<typeof captureIo>; hostConfig: any } {
  const io = captureIo();
  return {
    io,
    home: m.guardHome,
    hostConfig,
    paths: resolveHostPaths({ OPENCLAW_STATE_DIR: m.stateDir }, hostConfig, m.home),
    env: {},
    fetchFn: mock.fetch,
    sleep: noSleep,
    hostname: 'test-box',
    configWriter: async (mutate: (draft: any) => void) => mutate(hostConfig),
    ...overrides,
  } as any;
}

describe('setup', () => {
  test('non-interactive: enrolls, writes config and key (0600, home 0700), configures OpenClaw, self-tests', async () => {
    mock.enrollmentPoll = [
      { status: 400, body: { error: 'authorization_pending' } },
      { status: 400, body: { error: 'slow_down' } },
    ];
    const hostConfig: any = { mcp: { servers: { github: { command: 'gh-mcp' }, 'My Mail': { url: 'https://x' }, off: { enabled: false } } } };
    const d = deps({}, hostConfig);
    await setupCommand(d, { url: `${ORIGIN}/orgs/acme/portal`, preset: 'builder', approvals: 'auto', yes: true, name: 'Test agent' });
    const out = d.io.text();
    assert.equal(d.io.exitCode, 0, out);

    // The four steps, the verification URL, the user code and the fingerprint.
    for (const s of ['Step 1 of 4', 'Step 2 of 4', 'Step 3 of 4', 'Step 4 of 4']) assert.ok(out.includes(s), s);
    assert.ok(out.includes(`${ORIGIN}/orgs/acme/portal/agents/enroll?code=BCDF-GHJK`));
    assert.ok(out.includes('BCDF-GHJK'));
    const config = JSON.parse(readFileSync(m.guardHome.configPath, 'utf8'));
    assert.ok(out.includes(keyFingerprint(config.keyId)));
    assert.match(out, /Granted without asking \(3\)/);
    assert.match(out, /Audit receipt delivered/);
    assert.match(out, /Doctor/);

    // Files.
    assert.equal(statSync(m.guardHome.keyPath).mode & 0o777, 0o600);
    assert.equal(statSync(m.guardHome.configPath).mode & 0o777, 0o600);
    assert.equal(statSync(m.guardDir).mode & 0o777, 0o700);
    assert.match(config.agentId, /^agt_/);
    assert.equal(config.preset, 'builder');
    assert.equal(config.canActOnBehalfOfUsers, true);
    assert.equal(config.issuer, `${ORIGIN}/orgs/acme/api/v1`);
    assert.ok(!readFileSync(m.guardHome.configPath, 'utf8').includes('PRIVATE KEY'));
    assert.ok(!out.includes('PRIVATE KEY') && !out.includes('at_'), 'no key or token printed');

    // The enrollment request.
    const req = mock.enrollmentsStarted.at(-1);
    assert.equal(req.name, 'Test agent');
    assert.equal(req.host, 'openclaw');
    assert.equal(req.host_label, 'test-box');
    assert.equal(req.delegation, true);
    assert.equal(req.jwks.keys.length, 1);
    assert.equal(req.jwks.keys[0].d, undefined, 'public key only');
    assert.deepEqual(req.inventory.mcp_servers, [{ name: 'github' }, { name: 'My Mail' }]);
    const scopes = Object.fromEntries(req.capabilities.map((c: any) => [c.scope, c.checked]));
    assert.equal(scopes['shell:exec'], true, 'builder ticks shell:exec');
    assert.equal(scopes['messages:send'], false, 'never pre-ticked');
    assert.equal(scopes['mcp:github:read:*'], true);
    assert.equal(scopes['mcp:my_mail:destructive:*'], false);

    // OpenClaw config through the host writer.
    assert.equal(hostConfig.plugins.entries.lumoauth.enabled, true);
    assert.equal(hostConfig.plugins.entries.lumoauth.hooks.timeouts.before_tool_call, 180000);

    // Self-test receipt.
    assert.ok(mock.receipts.some((r) => r.tool === 'lumoauth.selftest' && r.decision === 'allowed'));
  });

  test('without a config writer it prints the exact openclaw config set commands', async () => {
    const d = deps({ configWriter: undefined });
    await setupCommand(d, { url: `${ORIGIN}/orgs/acme`, approvals: 'host', yes: true });
    const out = d.io.text();
    assert.match(out, /openclaw config set plugins\.entries\.lumoauth\.enabled true/);
    assert.doesNotMatch(out, /hooks\.timeouts/, 'host approvals do not need the long timeout');
  });

  test('denied in LumoAuth: an error, and no key or config left behind', async () => {
    mock.enrollmentPoll = [{ status: 400, body: { error: 'access_denied' } }];
    const d = deps();
    await assert.rejects(setupCommand(d, { url: `${ORIGIN}/orgs/acme`, yes: true }), /denied in LumoAuth/);
    assert.equal(existsSync(m.guardHome.keyPath), false);
    assert.equal(existsSync(m.guardHome.configPath), false);
  });

  test('a fingerprint mismatch stops setup', async () => {
    mock.enrollmentFingerprint = 'AAAA-BBBB-CCCC-DDDD';
    const d = deps();
    await assert.rejects(setupCommand(d, { url: `${ORIGIN}/orgs/acme`, yes: true }), /fingerprint/);
  });

  test('non-interactive without --url explains what to pass', async () => {
    await assert.rejects(setupCommand(deps(), { yes: true }), /Pass --url/);
  });

  test('already set up: says so unless --force', async () => {
    setUpGuard(m.guardHome, mock);
    const d = deps();
    await setupCommand(d, { url: `${ORIGIN}/orgs/acme`, yes: true });
    assert.match(d.io.text(), /Already set up/);
    assert.equal(mock.enrollmentsStarted.filter((e) => e.host_label === 'never').length, 0);
  });

  test('interactive: asks for the URL and the preset', async () => {
    const io = captureIo({ tty: true, answers: [`${ORIGIN}/orgs/acme/portal`, '1'] });
    const d = deps({ io });
    await setupCommand(d, { approvals: 'host' });
    assert.equal(JSON.parse(readFileSync(m.guardHome.configPath, 'utf8')).preset, 'observer');
  });
});

describe('URL and checklist helpers', () => {
  test('parseDashboardUrl takes the origin and the organization', () => {
    assert.deepEqual(parseDashboardUrl('https://app.lumoauth.dev/orgs/acme/portal'), { baseUrl: 'https://app.lumoauth.dev', orgId: 'acme' });
    assert.deepEqual(parseDashboardUrl('eu.app.lumoauth.dev/orgs/x-1'), { baseUrl: 'https://eu.app.lumoauth.dev', orgId: 'x-1' });
    assert.throws(() => parseDashboardUrl('http://app.lumoauth.dev/orgs/a'), /https/);
  });
  test('checklist: every catalog capability once, at most 200, canonical scopes', () => {
    const list = capabilityChecklist('assistant', Array.from({ length: 50 }, (_, i) => `s${i}`));
    assert.ok(list.length <= 200);
    assert.equal(new Set(list.map((c) => c.scope)).size, list.length);
    assert.ok(list.every((c) => /^[a-z0-9_*-]+(:[a-z0-9_*-]+)*$/.test(c.scope) && c.label.length <= 120));
  });
});

describe('status, doctor, lock, unlock, reset', () => {
  test('status --json reports identity, settings and live connectivity', async () => {
    const { agentId } = setUpGuard(m.guardHome, mock, { capabilities: ['files:read'] });
    const d = deps();
    const report: any = await statusCommand(d, { json: true });
    assert.equal(report.setUp, true);
    assert.equal(report.agent.agentId, agentId);
    assert.equal(report.connectivity.ok, true);
    assert.deepEqual(report.connectivity.capabilities, ['files:read']);
    const printed = JSON.parse(d.io.lines.join('\n'));
    assert.equal(printed.agent.agentId, agentId);
    assert.ok(!d.io.text().includes('PRIVATE KEY'));
  });

  test('status when not set up', async () => {
    const d = deps();
    await statusCommand(d, {});
    assert.match(d.io.text(), /Not set up/);
  });

  test('status shows the gateway report (recent decisions, receipts)', async () => {
    setUpGuard(m.guardHome, mock);
    writeFileSync(
      m.guardHome.statusPath,
      JSON.stringify({ updatedAt: new Date().toISOString(), receipts: { sent: 3, queued: 1, pending: 0, dropped: 0 }, recent: [{ at: 'now', tool: 'exec', capability: 'shell:exec', decision: 'blocked', reason: 'hard_rule' }] }),
    );
    const d = deps();
    await statusCommand(d, { offline: true });
    assert.match(d.io.text(), /Receipts: 3 sent, 1 queued/);
    assert.match(d.io.text(), /blocked\s+exec/);
  });

  test('doctor --json lists every required check; critical findings set the exit code', async () => {
    setUpGuard(m.guardHome, mock);
    const d = deps({}, { channels: { discord: { dmPolicy: 'open' } }, gateway: { bind: 'lan', auth: { mode: 'none' } }, tools: { elevated: { enabled: true, allowFrom: { discord: ['*'] } } } });
    const checks = await doctorCommand(d, { json: true });
    const ids = checks.map((c) => c.id);
    for (const id of [
      'guard.setup', 'guard.connectivity', 'guard.approvals', 'guard.hook-timeout', 'secrets.plaintext', 'fs.permissions',
      'openclaw.sandbox', 'openclaw.exec', 'openclaw.elevated', 'openclaw.dm-policy', 'openclaw.gateway-bind', 'openclaw.config-readonly', 'openclaw.plugins-allowlist',
    ]) assert.ok(ids.includes(id), id);
    const by = Object.fromEntries(checks.map((c) => [c.id, c.level]));
    assert.equal(by['guard.connectivity'], 'ok');
    assert.equal(by['openclaw.dm-policy'], 'critical');
    assert.equal(by['openclaw.gateway-bind'], 'critical');
    assert.equal(by['openclaw.elevated'], 'critical');
    assert.equal(by['openclaw.sandbox'], 'warn');
    assert.equal(d.io.exitCode, 1);
  });

  test('doctor: plaintext secrets are counted, never printed; loose permissions found', async () => {
    setUpGuard(m.guardHome, mock);
    writeFileSync(join(m.stateDir, '.env'), 'OPENAI_API_KEY=sk-live-secret\nOTHER=1\n', { mode: 0o644 });
    const d = deps({}, { models: { providers: { openai: { apiKey: 'sk-in-config' } } } });
    const checks = await doctorCommand(d, { offline: true });
    const plain = checks.find((c) => c.id === 'secrets.plaintext')!;
    assert.equal(plain.level, 'warn');
    assert.match(plain.finding, /1 secret value/);
    assert.equal(checks.find((c) => c.id === 'fs.permissions')!.level, 'warn');
    assert.ok(!d.io.text().includes('sk-live-secret') && !d.io.text().includes('sk-in-config'));
  });

  test('doctor: a disabled plugin, a short hook timeout with LumoAuth approvals', async () => {
    setUpGuard(m.guardHome, mock, { config: { approvals: 'lumoauth', canActOnBehalfOfUsers: true } });
    const d = deps({}, { plugins: { entries: { lumoauth: { enabled: false, hooks: { timeouts: { before_tool_call: 15000 } } } } } });
    const checks = await doctorCommand(d, { offline: true });
    assert.equal(checks.find((c) => c.id === 'guard.setup')!.level, 'critical');
    const t = checks.find((c) => c.id === 'guard.hook-timeout')!;
    assert.equal(t.level, 'warn');
    assert.match(String(t.fix), /before_tool_call 180000/);
  });

  test('lock, unlock and reset', async () => {
    const { agentId } = setUpGuard(m.guardHome, mock);
    const d = deps();
    lockCommand(d, 'going on holiday');
    assert.match(readFileSync(m.guardHome.lockPath, 'utf8'), /going on holiday/);
    assert.equal(statSync(m.guardHome.lockPath).mode & 0o777, 0o600);
    unlockCommand(d);
    assert.equal(existsSync(m.guardHome.lockPath), false);
    await assert.rejects(resetCommand(d, {}), /--yes/);
    await resetCommand(d, { yes: true });
    assert.equal(existsSync(m.guardHome.keyPath), false);
    assert.equal(existsSync(m.guardHome.configPath), false);
    assert.ok(d.io.text().includes(agentId));
  });
});

describe('commander wiring', () => {
  class FakeCommand {
    children = new Map<string, FakeCommand>();
    options: string[] = [];
    args: string[] = [];
    fn: ((...a: any[]) => unknown) | undefined;
    command(name: string) {
      const c = new FakeCommand();
      this.children.set(name, c);
      return c;
    }
    description() {
      return this;
    }
    option(flags: string) {
      this.options.push(flags);
      return this;
    }
    argument(name: string) {
      this.args.push(name);
      return this;
    }
    action(fn: (...a: any[]) => unknown) {
      this.fn = fn;
      return this;
    }
  }

  test('openclaw lumoauth setup|status|doctor|lock|unlock|reset are registered and run', async () => {
    setUpGuard(m.guardHome, mock);
    const program = new FakeCommand();
    const io = captureIo();
    registerLumoauthCli({ program, config: {}, logger: { info() {}, warn() {}, error() {} } } as any, {
      home: () => m.guardHome,
      paths: () => resolveHostPaths({ OPENCLAW_STATE_DIR: m.stateDir }, {}, m.home),
      configWriter: () => undefined,
      io: () => io,
    });
    const root = program.children.get('lumoauth')!;
    assert.deepEqual([...root.children.keys()], ['setup', 'status', 'doctor', 'lock', 'unlock', 'reset']);
    assert.ok(root.children.get('setup')!.options.some((o) => o.startsWith('--url')));
    await root.children.get('lock')!.fn!(['from', 'cli'], {});
    assert.match(readFileSync(m.guardHome.lockPath, 'utf8'), /from cli/);
    await root.children.get('unlock')!.fn!({});
    await root.children.get('reset')!.fn!({});
    assert.match(io.errors.join('\n'), /--yes/);
    assert.equal(io.exitCode, 1);
  });
});
