import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { GuardConfig } from '../../src/config.ts';
import { GuardHome } from '../../src/guard-home.ts';
import type { CliIo } from '../../src/cli/io.ts';
import { generateAgentKey, jwkThumbprint, privateKeyToPem, publicJwk } from '../../src/lumoauth/crypto.ts';
import { ISSUER, ORG, ORIGIN, TOKEN_ENDPOINT, type MockLumoAuth } from './mock-lumoauth.ts';

export function tempDir(prefix = 'lumoauth-guard-test-'): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A fake machine: home, OpenClaw state dir with a workspace, Guard home. */
export function fakeMachine() {
  const t = tempDir();
  const home = join(t.dir, 'home');
  const stateDir = join(home, '.openclaw');
  const workspace = join(stateDir, 'workspace');
  const guardDir = join(home, '.lumoauth', 'guard', 'openclaw');
  mkdirSync(workspace, { recursive: true });
  return { ...t, home, stateDir, workspace, guardDir, guardHome: new GuardHome(guardDir) };
}

/** Enroll an agent with the mock and write config.json + agent-key.pem. */
export function setUpGuard(
  guardHome: GuardHome,
  mock: MockLumoAuth,
  opts: { capabilities?: string[]; status?: string; config?: Partial<GuardConfig> } = {},
): { agentId: string; config: GuardConfig } {
  const key = generateAgentKey();
  const jwk = publicJwk(key);
  const kid = jwkThumbprint(jwk);
  const agentId = `agt_${kid.slice(0, 16).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`;
  mock.addAgent(agentId, { ...jwk, kid }, opts.capabilities ?? ['files:read', 'files:write'], opts.status ?? 'active');
  const config: GuardConfig = {
    version: 1,
    baseUrl: ORIGIN,
    orgId: ORG,
    agentId,
    issuer: ISSUER,
    tokenEndpoint: TOKEN_ENDPOINT,
    keyId: kid,
    ownerUserId: '0197aaaa-bbbb-7ccc-8ddd-eeeeffff0000',
    canActOnBehalfOfUsers: false,
    preset: 'assistant',
    decisionMode: 'local',
    approvals: 'host',
    onUngranted: 'ask',
    taint: { enabled: true, windowSeconds: 1800, escalate: ['external'] },
    refreshSeconds: 60,
    offlineGraceSeconds: 300,
    receipts: true,
    rememberApprovals: true,
    extraProtectedPaths: [],
    allowPaths: [],
    ...opts.config,
  };
  guardHome.ensure();
  guardHome.writeKey(privateKeyToPem(key));
  guardHome.writeConfig(config);
  return { agentId, config };
}

export function captureIo(opts: { tty?: boolean; answers?: string[] } = {}): CliIo & { lines: string[]; errors: string[]; exitCode: number; text(): string } {
  const lines: string[] = [];
  const errors: string[] = [];
  const answers = [...(opts.answers ?? [])];
  const io = {
    lines,
    errors,
    exitCode: 0,
    out: (line = '') => void lines.push(line),
    err: (line: string) => void errors.push(line),
    status: () => {},
    clearStatus: () => {},
    isTTY: opts.tty === true,
    color: false,
    prompt: opts.tty ? async () => answers.shift() ?? '' : undefined,
    setExitCode(code: number) {
      io.exitCode = code;
    },
    text: () => [...lines, ...errors].join('\n'),
  };
  return io;
}

export const noSleep = async () => {};
