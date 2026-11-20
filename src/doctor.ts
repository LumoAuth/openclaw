import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { GuardConfig } from './config.ts';
import { DEFAULT_HOOK_TIMEOUT_MS, PLUGIN_ID } from './guard.ts';
import { GuardHome, IS_POSIX } from './guard-home.ts';
import type { HostPaths } from './host/host-env.ts';
import type { OpenClawConfigLike, SecurityAuditFinding } from './host/openclaw-types.ts';
import { AgentClient } from './lumoauth/agent-client.ts';
import type { FetchFn } from './lumoauth/http.ts';
import { LumoAuthError } from './lumoauth/http.ts';
import { packageVersion } from './package-root.ts';

export type CheckLevel = 'ok' | 'info' | 'warn' | 'critical';

export interface DoctorCheck {
  id: string;
  level: CheckLevel;
  finding: string;
  fix?: string;
}

export interface DoctorOptions {
  home: GuardHome;
  hostConfig: OpenClawConfigLike | undefined;
  paths: HostPaths;
  env?: NodeJS.ProcessEnv;
  /** Contact LumoAuth (token + /agents/me). Off: connectivity is reported from the last known state. */
  live?: boolean;
  fetchFn?: FetchFn | undefined;
  /** Result of the gateway's last refresh (status.json), used when live is false. */
  lastKnown?: { status?: string; error?: string } | undefined;
}

const LEVEL_ORDER: Record<CheckLevel, number> = { ok: 0, info: 1, warn: 2, critical: 3 };

function get(obj: any, path: string): any {
  let cur = obj;
  for (const part of path.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

/** Effective before_tool_call timeout for this plugin (OpenClaw: hooks.timeouts[hook] → hooks.timeoutMs → the registration's own). */
export function effectiveHookTimeoutMs(hostConfig: OpenClawConfigLike | undefined): number {
  const hooks = get(hostConfig, `plugins.entries.${PLUGIN_ID}.hooks`);
  const specific = hooks?.timeouts?.before_tool_call;
  if (typeof specific === 'number' && specific > 0) return specific;
  if (typeof hooks?.timeoutMs === 'number' && hooks.timeoutMs > 0) return hooks.timeoutMs;
  return DEFAULT_HOOK_TIMEOUT_MS;
}

/** Approvals may go through LumoAuth push (needs the long hook timeout). */
export function mayUseLumoAuthApprovals(config: GuardConfig): boolean {
  return config.approvals === 'lumoauth' || (config.approvals === 'auto' && config.canActOnBehalfOfUsers && !!config.ownerUserId);
}

function modeOf(path: string): number | undefined {
  try {
    return statSync(path).mode & 0o777;
  } catch {
    return undefined;
  }
}

function octal(mode: number): string {
  return `0${mode.toString(8).padStart(3, '0')}`;
}

function checkSetup(o: DoctorOptions, loaded: ReturnType<GuardHome['readConfig']>): DoctorCheck {
  const h = o.home;
  const problems: string[] = [];
  const fixes: string[] = [];
  if (!loaded.exists || !h.hasKey()) {
    return { id: 'guard.setup', level: 'critical', finding: 'LumoAuth Guard is not set up: OpenClaw blocks every tool call.', fix: 'openclaw lumoauth setup' };
  }
  if (!loaded.config) {
    return { id: 'guard.setup', level: 'critical', finding: `The Guard configuration cannot be used: ${loaded.error}.`, fix: 'openclaw lumoauth reset, then openclaw lumoauth setup' };
  }
  try {
    h.readKey();
  } catch (err) {
    return { id: 'guard.setup', level: 'critical', finding: `agent-key.pem cannot be used: ${(err as Error).message}.`, fix: 'openclaw lumoauth reset, then openclaw lumoauth setup' };
  }
  const plugins = get(o.hostConfig, 'plugins');
  if (plugins?.enabled === false) problems.push('all plugins are switched off (plugins.enabled: false)');
  if (get(plugins, `entries.${PLUGIN_ID}.enabled`) === false) {
    problems.push('the plugin is disabled');
    fixes.push(`openclaw plugins enable ${PLUGIN_ID}`);
  }
  if (Array.isArray(plugins?.allow) && plugins.allow.length > 0 && !plugins.allow.includes(PLUGIN_ID)) {
    problems.push('plugins.allow does not list lumoauth, so the plugin does not load');
  }
  if (Array.isArray(plugins?.deny) && plugins.deny.includes(PLUGIN_ID)) problems.push('plugins.deny lists lumoauth');
  if (problems.length) {
    return { id: 'guard.setup', level: 'critical', finding: `Set up, but OpenClaw does not run the Guard: ${problems.join('; ')}.`, fix: fixes.join('; ') || 'Edit the plugins section of openclaw.json.' };
  }
  if (IS_POSIX) {
    const dirMode = modeOf(h.dir);
    if (dirMode !== undefined && dirMode !== 0o700) {
      problems.push(`the Guard home is ${octal(dirMode)}`);
      fixes.push(`chmod 700 ${h.dir}`);
    }
    for (const f of [h.configPath, h.keyPath]) {
      const m = modeOf(f);
      if (m !== undefined && (m & 0o077) !== 0) {
        problems.push(`${f.slice(h.dir.length + 1)} is ${octal(m)}`);
        fixes.push(`chmod 600 ${f}`);
      }
    }
  }
  if (problems.length) return { id: 'guard.setup', level: 'warn', finding: `Set up, but ${problems.join(', ')}.`, fix: fixes.join(' && ') };
  const issues = loaded.issues.length ? ` ${loaded.issues.length} config value(s) fell back to defaults (see status).` : '';
  return { id: 'guard.setup', level: issues ? 'warn' : 'ok', finding: `Set up as agent ${loaded.config.agentId} (${loaded.config.orgId}), version ${packageVersion()}.${issues}` };
}

async function checkConnectivity(o: DoctorOptions, config: GuardConfig | null): Promise<DoctorCheck> {
  const id = 'guard.connectivity';
  if (!config) return { id, level: 'info', finding: 'Not checked: the Guard is not set up.' };
  if (!o.live) {
    if (o.lastKnown?.error) return { id, level: 'warn', finding: `Last refresh failed: ${o.lastKnown.error}`, fix: 'openclaw lumoauth status' };
    if (o.lastKnown?.status && o.lastKnown.status !== 'active') {
      return { id, level: 'critical', finding: `The agent is ${o.lastKnown.status} in LumoAuth: every tool call is blocked.`, fix: 'Reactivate the agent in LumoAuth.' };
    }
    return { id, level: 'info', finding: 'Not checked live (run openclaw lumoauth doctor).' };
  }
  try {
    const client = new AgentClient({
      baseUrl: config.baseUrl,
      orgId: config.orgId,
      agentId: config.agentId,
      issuer: config.issuer,
      tokenEndpoint: config.tokenEndpoint,
      keyId: config.keyId,
      key: o.home.readKey(),
      fetchFn: o.fetchFn,
      userAgent: `lumoauth-openclaw/${packageVersion()}`,
    });
    const me = await client.me();
    const status = typeof me.identity?.status === 'string' ? me.identity.status : 'unknown';
    const caps = Array.isArray(me.capabilities) ? me.capabilities.length : 0;
    if (status !== 'active') {
      return { id, level: 'critical', finding: `The agent is ${status} in LumoAuth: every tool call is blocked.`, fix: 'Reactivate the agent in LumoAuth.' };
    }
    return { id, level: 'ok', finding: `LumoAuth accepts the agent's key; the agent is active with ${caps} capabilities.` };
  } catch (err) {
    const e = err as LumoAuthError;
    if (e?.kind === 'auth') {
      return { id, level: 'critical', finding: `LumoAuth refuses this agent's key (${e.message}). Every tool call is blocked.`, fix: 'The agent or its key was removed in LumoAuth: run openclaw lumoauth reset, then openclaw lumoauth setup.' };
    }
    return { id, level: 'warn', finding: `Cannot reach LumoAuth: ${e?.message ?? err}. Calls are blocked once the offline grace (${config.offlineGraceSeconds} s) runs out.`, fix: `Check the network and ${config.baseUrl}.` };
  }
}

function checkApprovals(config: GuardConfig | null): DoctorCheck {
  const id = 'guard.approvals';
  if (!config) return { id, level: 'info', finding: 'Not checked: the Guard is not set up.' };
  const host = 'OpenClaw asks in the Control UI and on chat channels that support approvals; runs with no one to answer (cron, heartbeat) are blocked.';
  switch (config.approvals) {
    case 'off':
      return { id, level: 'warn', finding: 'Approvals are off: every call that needs approval is blocked.', fix: 'Set "approvals": "auto" in the Guard config.json, or grant the capabilities in LumoAuth.' };
    case 'host':
      return { id, level: 'ok', finding: `Approvals in OpenClaw. ${host}` };
    case 'lumoauth':
      if (!config.canActOnBehalfOfUsers || !config.ownerUserId) {
        return { id, level: 'critical', finding: 'Approvals are set to the LumoAuth app, but the agent may not act on behalf of its owner: every approval is refused.', fix: 'Turn on delegation for the agent in LumoAuth, or set "approvals": "auto".' };
      }
      return { id, level: 'ok', finding: "Approvals in the owner's LumoAuth app." };
    default:
      if (config.canActOnBehalfOfUsers && config.ownerUserId) {
        return { id, level: 'ok', finding: "Approvals in the owner's LumoAuth app; OpenClaw's approval UI when the app cannot be reached." };
      }
      return { id, level: 'info', finding: `Approvals in OpenClaw (delegation is off in LumoAuth). ${host}` };
  }
}

function checkHookTimeout(o: DoctorOptions, config: GuardConfig | null): DoctorCheck {
  const id = 'guard.hook-timeout';
  const ms = effectiveHookTimeoutMs(o.hostConfig);
  if (config && mayUseLumoAuthApprovals(config) && ms < 150_000) {
    return {
      id,
      level: 'warn',
      finding: `The hook timeout is ${Math.round(ms / 1000)} s; a LumoAuth approval can take longer and the call is then blocked.`,
      fix: `openclaw config set plugins.entries.${PLUGIN_ID}.hooks.timeouts.before_tool_call 180000`,
    };
  }
  return { id, level: 'ok', finding: `The hook timeout is ${Math.round(ms / 1000)} s.` };
}

const SECRET_KEY_NAME = /(api[_-]?key|apikey|token|secret|password|passwd|credential|private[_-]?key)$/i;

function countPlaintextInConfig(value: unknown, keyName = '', depth = 0): number {
  if (depth > 20 || value === null || value === undefined) return 0;
  if (typeof value === 'string') {
    if (!SECRET_KEY_NAME.test(keyName)) return 0;
    const v = value.trim();
    if (v === '' || /^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(v) || v.startsWith('secret://') || v.startsWith('env:')) return 0;
    return 1;
  }
  if (Array.isArray(value)) return value.reduce((n, v) => n + countPlaintextInConfig(v, keyName, depth + 1), 0);
  if (typeof value === 'object') {
    // A SecretRef ({ source, id }) is not plaintext.
    const rec = value as Record<string, unknown>;
    if (typeof rec.source === 'string' && typeof rec.id === 'string') return 0;
    return Object.entries(rec).reduce((n, [k, v]) => n + countPlaintextInConfig(v, k, depth + 1), 0);
  }
  return 0;
}

function countPlaintextInDotenv(path: string): number {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return 0;
  }
  let n = 0;
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (m && /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)/i.test(m[1]!) && m[2]!.replace(/^['"]|['"]$/g, '').trim() !== '') n++;
  }
  return n;
}

function checkPlaintext(o: DoctorOptions): DoctorCheck {
  const id = 'secrets.plaintext';
  const inConfig = countPlaintextInConfig(o.hostConfig);
  const envPath = join(o.paths.stateDir, '.env');
  const inEnv = countPlaintextInDotenv(envPath);
  if (inConfig > 0) {
    return {
      id,
      level: 'warn',
      finding: `openclaw.json holds ${inConfig} secret value(s) in plaintext${inEnv ? `, and ${envPath} holds ${inEnv}` : ''}.`,
      fix: 'Move them to SecretRefs or environment variables (openclaw secrets), and keep these files mode 0600.',
    };
  }
  if (inEnv > 0) {
    return { id, level: 'info', finding: `${envPath} holds ${inEnv} secret value(s); the Guard blocks the agent from reading it.`, fix: `Keep it mode 0600: chmod 600 ${envPath}` };
  }
  return { id, level: 'ok', finding: 'No plaintext secrets found in openclaw.json or the state .env.' };
}

function checkPermissions(o: DoctorOptions): DoctorCheck {
  const id = 'fs.permissions';
  if (!IS_POSIX) return { id, level: 'info', finding: 'Not checked on Windows.' };
  const loose: string[] = [];
  const consider = (p: string) => {
    const m = modeOf(p);
    if (m !== undefined && (m & 0o077) !== 0) loose.push(p);
  };
  consider(o.paths.configPath);
  consider(join(o.paths.stateDir, '.env'));
  const walk = (dir: string, depth: number) => {
    if (depth > 4 || !existsSync(dir)) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries.slice(0, 500)) {
      const p = join(dir, e);
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(p, depth + 1);
      else if ((st.mode & 0o077) !== 0) loose.push(p);
    }
  };
  walk(join(o.paths.stateDir, 'credentials'), 0);
  const agentsDir = join(o.paths.stateDir, 'agents');
  if (existsSync(agentsDir)) {
    try {
      for (const a of readdirSync(agentsDir).slice(0, 100)) walk(join(agentsDir, a, 'agent'), 0);
    } catch {
      // ignore
    }
  }
  if (loose.length) {
    const shown = loose.slice(0, 3).join(', ');
    return {
      id,
      level: 'warn',
      finding: `${loose.length} OpenClaw config or credential file(s) can be read by other users: ${shown}${loose.length > 3 ? ', …' : ''}.`,
      fix: `chmod 600 ${loose.slice(0, 3).join(' ')}${loose.length > 3 ? ' …' : ''} (or run openclaw security audit --fix)`,
    };
  }
  return { id, level: 'ok', finding: 'OpenClaw config and credential files are private to your user.' };
}

function checkSandbox(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const mode = get(cfg, 'agents.defaults.sandbox.mode');
  if (mode === 'all' || mode === 'non-main') return { id: 'openclaw.sandbox', level: 'ok', finding: `Sandbox mode is ${mode}.` };
  return {
    id: 'openclaw.sandbox',
    level: 'warn',
    finding: 'The sandbox is off: commands run directly as your user. The Guard scans commands, but a scan is a tripwire, not a sandbox.',
    fix: 'openclaw config set agents.defaults.sandbox.mode non-main',
  };
}

function checkExec(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const exec = get(cfg, 'tools.exec') ?? {};
  const sandbox = get(cfg, 'agents.defaults.sandbox.mode');
  const full = exec.mode === 'full' || exec.security === 'full';
  if (full && sandbox !== 'all' && sandbox !== 'non-main') {
    return {
      id: 'openclaw.exec',
      level: 'warn',
      finding: 'Exec runs any command without OpenClaw asking (tools.exec full) and without a sandbox.',
      fix: 'openclaw config set tools.exec.mode ask (or turn on the sandbox)',
    };
  }
  return { id: 'openclaw.exec', level: 'ok', finding: `Exec mode is ${exec.mode ?? exec.security ?? 'the default'}.` };
}

function checkElevated(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const el = get(cfg, 'tools.elevated');
  if (el?.enabled === true) {
    const from = el.allowFrom;
    const lists: unknown[] = Array.isArray(from) ? [from] : from && typeof from === 'object' ? Object.values(from) : [];
    const wildcard = lists.some((l) => Array.isArray(l) && l.some((x) => String(x).trim() === '*'));
    if (wildcard) {
      return { id: 'openclaw.elevated', level: 'critical', finding: 'Elevated mode is on and anyone (allowFrom "*") can use it.', fix: 'List the allowed senders in tools.elevated.allowFrom, or: openclaw config set tools.elevated.enabled false' };
    }
    return { id: 'openclaw.elevated', level: 'ok', finding: 'Elevated mode is on for listed senders only.' };
  }
  return { id: 'openclaw.elevated', level: 'ok', finding: 'Elevated mode is off.' };
}

function checkDmPolicy(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const open: string[] = [];
  const channels = get(cfg, 'channels');
  if (channels && typeof channels === 'object') {
    for (const [name, ch] of Object.entries(channels as Record<string, any>)) {
      if (ch?.dmPolicy === 'open') open.push(name);
      if (ch?.accounts && typeof ch.accounts === 'object') {
        for (const [acct, a] of Object.entries(ch.accounts as Record<string, any>)) if (a?.dmPolicy === 'open') open.push(`${name}.${acct}`);
      }
    }
  }
  if (open.length) {
    return {
      id: 'openclaw.dm-policy',
      level: 'critical',
      finding: `Anyone can message the agent directly on: ${open.join(', ')} (dmPolicy open).`,
      fix: `openclaw config set channels.${open[0]!.split('.')[0]}.dmPolicy pairing`,
    };
  }
  return { id: 'openclaw.dm-policy', level: 'ok', finding: 'No channel accepts direct messages from anyone.' };
}

function checkGatewayBind(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const bind = get(cfg, 'gateway.bind') ?? 'loopback';
  const auth = get(cfg, 'gateway.auth') ?? {};
  const funnel = get(cfg, 'gateway.tailscale.mode') === 'funnel';
  const exposed = bind !== 'loopback' || funnel;
  if (!exposed) return { id: 'openclaw.gateway-bind', level: 'ok', finding: 'The gateway listens on loopback only.' };
  if (auth.mode === 'none') {
    return {
      id: 'openclaw.gateway-bind',
      level: 'critical',
      finding: `The gateway is reachable beyond this machine (${funnel ? 'Tailscale Funnel' : `bind ${bind}`}) without authentication.`,
      fix: 'openclaw config set gateway.auth.mode token (or bind it to loopback)',
    };
  }
  return { id: 'openclaw.gateway-bind', level: 'info', finding: `The gateway is reachable beyond this machine (${funnel ? 'Tailscale Funnel' : `bind ${bind}`}) with ${auth.mode ?? 'default'} authentication.` };
}

function checkConfigReadonly(env: NodeJS.ProcessEnv): DoctorCheck {
  if (env.OPENCLAW_CONFIG_READONLY && env.OPENCLAW_CONFIG_READONLY !== '0' && env.OPENCLAW_CONFIG_READONLY !== 'false') {
    return { id: 'openclaw.config-readonly', level: 'ok', finding: 'OpenClaw cannot change its own config (OPENCLAW_CONFIG_READONLY).' };
  }
  return {
    id: 'openclaw.config-readonly',
    level: 'info',
    finding: 'OPENCLAW_CONFIG_READONLY is not set: OpenClaw itself can change its config at runtime.',
    fix: 'Set OPENCLAW_CONFIG_READONLY=1 in the gateway environment when you do not change settings from chat.',
  };
}

function checkPluginsAllow(cfg: OpenClawConfigLike | undefined): DoctorCheck {
  const allow = get(cfg, 'plugins.allow');
  if (Array.isArray(allow) && allow.length > 0) return { id: 'openclaw.plugins-allowlist', level: 'ok', finding: `Only listed plugins load (${allow.length}).` };
  return {
    id: 'openclaw.plugins-allowlist',
    level: 'info',
    finding: 'plugins.allow is empty: every installed plugin can load.',
    fix: 'List the plugins you use in plugins.allow, including lumoauth.',
  };
}

/** SPEC §9: every check. Doctor never changes anything. */
export async function runDoctor(o: DoctorOptions): Promise<DoctorCheck[]> {
  const env = o.env ?? process.env;
  const loaded = o.home.readConfig();
  const config = loaded.config && o.home.hasKey() ? loaded.config : null;
  return [
    checkSetup(o, loaded),
    await checkConnectivity(o, config),
    checkApprovals(config),
    checkHookTimeout(o, config),
    checkPlaintext(o),
    checkPermissions(o),
    checkSandbox(o.hostConfig),
    checkExec(o.hostConfig),
    checkElevated(o.hostConfig),
    checkDmPolicy(o.hostConfig),
    checkGatewayBind(o.hostConfig),
    checkConfigReadonly(env),
    checkPluginsAllow(o.hostConfig),
  ];
}

export function worstLevel(checks: DoctorCheck[]): CheckLevel {
  return checks.reduce<CheckLevel>((w, c) => (LEVEL_ORDER[c.level] > LEVEL_ORDER[w] ? c.level : w), 'ok');
}

/** The checks as `openclaw security audit` findings (ok checks are left out). */
export function toAuditFindings(checks: DoctorCheck[]): SecurityAuditFinding[] {
  return checks
    .filter((c) => c.level !== 'ok')
    .map((c) => ({
      checkId: `plugins.${PLUGIN_ID}.${c.id}`,
      severity: c.level === 'critical' ? 'critical' : c.level === 'warn' ? 'warn' : 'info',
      title: `LumoAuth Guard: ${c.id}`,
      detail: c.finding,
      ...(c.fix ? { remediation: c.fix } : {}),
    }));
}
