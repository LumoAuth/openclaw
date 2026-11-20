import { registerLumoauthCli, CLI_DESCRIPTOR } from './cli/register.ts';
import { type HostConfigWriter } from './cli/commands.ts';
import { effectiveHookTimeoutMs, runDoctor, toAuditFindings } from './doctor.ts';
import { DEFAULT_HOOK_TIMEOUT_MS, Guard, PLUGIN_ID } from './guard.ts';
import { GuardHome, resolveGuardHome } from './guard-home.ts';
import { resolveHostPaths } from './host/host-env.ts';
import type {
  AfterToolCallEvent,
  BeforeToolCallEvent,
  CommandContext,
  LlmOutputEvent,
  OpenClawConfigLike,
  OpenClawPluginApiLike,
  ToolHookContext,
} from './host/openclaw-types.ts';
import { agentPortalUrl } from './config.ts';
import { packageRoot } from './package-root.ts';

/** SPEC §10.1: the lowest priority, so the Guard judges the parameters that the tool really gets. */
export const HOOK_PRIORITY = -1000;

interface Holder {
  api: OpenClawPluginApiLike | undefined;
  guard: Guard | undefined;
}

// One Guard per loaded module and Guard home: OpenClaw may call register()
// more than once (discovery, then full activation); taint, remembered
// approvals and timers must not be duplicated. (Module state, not a global:
// OpenClaw flags plugins that change process-wide state.)
const shared: Holder = { api: undefined, guard: undefined };
function holder(): Holder {
  return shared;
}

function safe<T>(fn: () => T): T | undefined {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

function currentHostConfig(api: OpenClawPluginApiLike): OpenClawConfigLike | undefined {
  return safe(() => api.runtime?.config?.current?.()) ?? api.config;
}

function hostStateDir(api: OpenClawPluginApiLike): string | undefined {
  return safe(() => api.runtime?.state?.resolveStateDir?.());
}

/** The Guard of this process (created on first use). */
export function getGuard(api: OpenClawPluginApiLike, overrides: Partial<ConstructorParameters<typeof Guard>[0]> = {}): Guard {
  const h = holder();
  h.api = api;
  const home = new GuardHome(resolveGuardHome());
  if (!h.guard || h.guard.home.dir !== home.dir) {
    if (h.guard) void h.guard.stop();
    h.guard = new Guard({
      home,
      logger: api.logger,
      hostConfig: () => (h.api ? currentHostConfig(h.api) : undefined),
      stateDir: () => (h.api ? hostStateDir(h.api) : undefined),
      pluginDir: api.rootDir ?? safe(() => packageRoot()),
      hookTimeoutMs: () => effectiveHookTimeoutMs(h.api ? currentHostConfig(h.api) : undefined),
      ...overrides,
    });
  }
  return h.guard;
}

/** Reset the process-wide Guard (tests). */
export async function resetGuardForTests(): Promise<void> {
  const h = holder();
  if (h.guard) await h.guard.stop();
  h.guard = undefined;
  h.api = undefined;
}

function configWriterFor(api: OpenClawPluginApiLike): HostConfigWriter | undefined {
  const mutate = safe(() => api.runtime?.config?.mutateConfigFile);
  if (typeof mutate !== 'function') return undefined;
  return async (change) => {
    await mutate({ afterWrite: { mode: 'auto' }, mutate: (draft) => change(draft) });
  };
}

export function register(api: OpenClawPluginApiLike, overrides: Partial<ConstructorParameters<typeof Guard>[0]> = {}): void {
  const mode = api.registrationMode ?? 'full';

  // The CLI is available in every mode (cli-metadata only collects its descriptor).
  api.registerCli?.(
    (ctx) =>
      registerLumoauthCli(ctx, {
        home: () => new GuardHome(resolveGuardHome()),
        paths: (config) => {
          const paths = resolveHostPaths(process.env, config);
          const fromHost = hostStateDir(api);
          return fromHost && !process.env.OPENCLAW_STATE_DIR ? resolveHostPaths({ ...process.env, OPENCLAW_STATE_DIR: fromHost }, config) : paths;
        },
        configWriter: () => configWriterFor(api),
      }),
    { descriptors: [CLI_DESCRIPTOR] },
  );

  if (mode === 'cli-metadata' || mode === 'setup-only' || mode === 'setup-runtime') return;

  const guard = getGuard(api, overrides);

  // The runtime gate. Registered in every mode that runs tools (full,
  // discovery, tool-discovery), so that no run dispatches tool calls without it.
  api.on?.(
    'before_tool_call',
    (event: BeforeToolCallEvent, ctx: ToolHookContext) => guard.beforeToolCall(event, ctx),
    { priority: HOOK_PRIORITY, timeoutMs: DEFAULT_HOOK_TIMEOUT_MS },
  );
  api.on?.('after_tool_call', (event: AfterToolCallEvent, ctx: ToolHookContext) => guard.afterToolCall(event, ctx), { priority: HOOK_PRIORITY });

  // Usage (SPEC §7.6) needs conversation access, which the owner grants explicitly.
  const access = currentHostConfig(api)?.plugins?.entries?.[PLUGIN_ID]?.hooks?.allowConversationAccess === true;
  if (access) api.on?.('llm_output', (event: LlmOutputEvent) => guard.onLlmOutput(event), { priority: HOOK_PRIORITY });

  api.registerCommand?.({
    name: 'lumoauth',
    description: 'LumoAuth Guard: show status, or lock every tool call (owner only)',
    acceptsArgs: true,
    requireAuth: true,
    requiredScopes: ['operator.write'],
    handler: (ctx: CommandContext) => chatCommand(guard, ctx),
  });

  api.registerSecurityAuditCollector?.(async (ctx) => {
    const config = ctx.config ?? currentHostConfig(api);
    const env = ctx.env ?? process.env;
    const paths = resolveHostPaths(ctx.stateDir && !env.OPENCLAW_STATE_DIR ? { ...env, OPENCLAW_STATE_DIR: ctx.stateDir } : env, config);
    const checks = await runDoctor({ home: guard.home, hostConfig: config, paths, env, live: true });
    return toAuditFindings(checks);
  });

  if (mode === 'full') {
    api.registerService?.({
      id: 'lumoauth-guard',
      start: () => guard.start({ viaService: true }),
      stop: () => guard.stop(),
    });
  }
}

/** `/lumoauth` in chat: status (default) and lock. Unlock is terminal-only. */
export function chatCommand(guard: Guard, ctx: CommandContext): { text: string } {
  if (ctx.senderIsOwner === false) return { text: 'Only the owner can use /lumoauth.' };
  const args = (ctx.args ?? '').trim();
  const [verb = 'status', ...rest] = args.split(/\s+/).filter(Boolean);
  switch (verb.toLowerCase()) {
    case 'lock': {
      const reason = rest.join(' ').slice(0, 200) || 'locked from chat';
      guard.home.lock(reason);
      return { text: '🔒 LumoAuth Guard is locked: every tool call is blocked. Unlock in a terminal: openclaw lumoauth unlock' };
    }
    case 'unlock':
      return { text: 'Unlocking is only possible in a terminal on the agent machine: openclaw lumoauth unlock' };
    case 'status':
    case '':
      return { text: chatStatus(guard) };
    default:
      return { text: 'Usage: /lumoauth [status | lock <reason>]' };
  }
}

function chatStatus(guard: Guard): string {
  const st = guard.loadState();
  const lock = guard.home.readLock();
  const lines = ['LumoAuth Guard'];
  if (!st) {
    lines.push('Not set up: every tool call is blocked. Run in a terminal: openclaw lumoauth setup');
  } else {
    const c = st.config;
    lines.push(`Agent: ${c.name ?? c.agentId} (${c.agentId}) in ${c.orgId}`);
    lines.push(`Approvals: ${c.approvals}; mode: ${c.decisionMode}; preset: ${c.preset}`);
    const snap = guard.snapshots.snapshot;
    const age = guard.snapshots.ageSeconds();
    lines.push(
      snap
        ? `LumoAuth: agent ${snap.status}, ${snap.capabilities.length} capabilities (checked ${Math.round(age ?? 0)} s ago)`
        : `LumoAuth: no capability snapshot${guard.snapshots.lastError ? ` (${guard.snapshots.lastError.message})` : ''}`,
    );
    for (const w of guard.pendingApprovals) lines.push(`Waiting for approval ${w.where}: ${w.tool} (${w.capability})`);
    const r = guard.receipts.snapshot();
    lines.push(`Receipts: ${r.sent} sent, ${r.queued} queued${r.dropped ? `, ${r.dropped} dropped` : ''}`);
    lines.push(`Agent page: ${agentPortalUrl(c)}`);
  }
  lines.push(lock ? `Lock: ON since ${lock.at}${lock.reason ? ` (${lock.reason})` : ''}` : 'Lock: off (/lumoauth lock to block every tool call)');
  const recent = guard.recent.slice(0, 5);
  if (recent.length) {
    lines.push('Recent:');
    for (const d of recent) lines.push(`  ${d.decision} ${d.tool} (${d.capability})`);
  }
  return lines.join('\n');
}
