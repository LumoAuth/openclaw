import { randomBytes } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { approvalArgumentLines, approvalText, cut } from './core/approval-text.ts';
import { argumentsSha256 } from './core/canonical-json.ts';
import { loadContract, type Contract } from './core/catalog.ts';
import { classify, type ClassifyResult } from './core/classify.ts';
import { decide, REASON_TEXT, type Decision, type ReasonCode } from './core/decide.ts';
import { compileShellRules, evaluateHardRules, type CompiledShellRules, type HardRuleResult } from './core/hard-rules.ts';
import { buildPathRules, type GuardEnv, type PathRules } from './core/paths.ts';
import { RememberedApprovals, TaintTracker } from './core/session-memory.ts';
import { agentPortalUrl, type GuardConfig } from './config.ts';
import { GuardHome } from './guard-home.ts';
import { buildGuardEnv, resolveHostPaths, type HostPaths } from './host/host-env.ts';
import type {
  AfterToolCallEvent,
  ApprovalResolution,
  BeforeToolCallEvent,
  BeforeToolCallResult,
  LlmOutputEvent,
  OpenClawConfigLike,
  PluginLogger,
  ToolHookContext,
} from './host/openclaw-types.ts';
import { AgentClient, type ToolCallReceipt } from './lumoauth/agent-client.ts';
import type { FetchFn } from './lumoauth/http.ts';
import { LumoAuthError } from './lumoauth/http.ts';
import { ReceiptQueue } from './lumoauth/receipts.ts';
import { SnapshotStore } from './lumoauth/snapshot.ts';
import { packageRoot, packageVersion } from './package-root.ts';

export const HOST = 'openclaw';
export const PLUGIN_ID = 'lumoauth';
/** Hook timeout that this plugin registers with (OpenClaw's default for before_tool_call is 15 s). */
export const DEFAULT_HOOK_TIMEOUT_MS = 180_000;
/** Approval wait for the host's approval UI (SPEC §10.1). */
export const HOST_APPROVAL_TIMEOUT_MS = 120_000;
const PUSH_POLL_MS = 2_000;
const RECENT_MAX = 20;
const STATUS_WRITE_MS = 10_000;
const USAGE_FLUSH_MS = 60_000;
const ASK_CACHE_MS = 30_000;
/** §4.1a: how long the decision for a dispatched call covers the inner call. */
const PRE_DECISION_MS = 60_000;

export interface RecentDecision {
  at: string;
  tool: string;
  capability: string;
  decision: ToolCallReceipt['decision'];
  reason: string;
}

export interface GuardOptions {
  home: GuardHome;
  logger?: PluginLogger | undefined;
  /** The live OpenClaw config (openclaw.json). */
  hostConfig?: (() => OpenClawConfigLike | undefined) | undefined;
  /** process.env by default. */
  env?: NodeJS.ProcessEnv | undefined;
  /** os.homedir() by default. */
  osHome?: string | undefined;
  /** OpenClaw's resolved state dir, when the host can tell. */
  stateDir?: (() => string | undefined) | undefined;
  pluginDir?: string | undefined;
  fetchFn?: FetchFn | undefined;
  now?: (() => number) | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  /** Push approvals give up this long before the host's hook timeout. */
  hookTimeoutMs?: (() => number) | undefined;
  platform?: string | undefined;
}

interface LoadedState {
  config: GuardConfig;
  issues: string[];
  client: AgentClient;
  signature: string;
}

type PushOutcome =
  | { kind: 'approved' }
  | { kind: 'refused' }
  | { kind: 'expired'; where: string }
  | { kind: 'unavailable'; code: string; text: string };

/** Where a LumoAuth approval can be answered, from the server's `delivery` list (§7.5). */
export function approvalWhere(delivery: string[] | undefined): string {
  const names: Record<string, string> = { push: 'on your phone', slack: 'in Slack', discord: 'in Discord' };
  const parts = (delivery ?? []).map((d) => names[d] ?? `in ${d}`).filter((v, i, a) => a.indexOf(v) === i);
  if (parts.length === 0) return 'in the LumoAuth app';
  if (parts.length === 1) return parts[0]!;
  return `${parts.slice(0, -1).join(', ')} or ${parts.at(-1)}`;
}

export interface PendingApproval {
  since: string;
  tool: string;
  capability: string;
  where: string;
}

type ReceiptBase = Omit<ToolCallReceipt, 'decision'>;

interface BlockExtra {
  hard: HardRuleResult;
  classified: ClassifyResult;
  config: GuardConfig;
  /** For approvals_off: why approval was needed. */
  underlying?: ReasonCode | undefined;
}

const silentLogger: PluginLogger = { info() {}, warn() {}, error() {} };

/**
 * LumoAuth Guard for one OpenClaw process: classifies each tool call,
 * applies the hard rules and the decision order (SPEC §5, §6), asks for
 * approvals, and reports receipts.
 */
export class Guard {
  readonly home: GuardHome;
  readonly taint = new TaintTracker();
  readonly remembered = new RememberedApprovals();
  readonly snapshots: SnapshotStore;
  readonly receipts: ReceiptQueue;
  readonly recent: RecentDecision[] = [];
  private readonly opts: GuardOptions;
  private readonly logger: PluginLogger;
  private readonly contract: Contract;
  private readonly now: () => number;
  private state: LoadedState | null = null;
  private stateError: string | undefined;
  private configStamp = '';
  private envCache = new Map<string, { env: GuardEnv; rules: PathRules; shell: CompiledShellRules }>();
  private envSignature = '';
  private readonly askCache = new Map<string, number>();
  private readonly pendingFallback = new Map<string, string[]>();
  /** §4.1a pre-decisions: (session, dispatched tool, argument digest) → the wrapper's receipt key. */
  private readonly preDecisions = new Map<string, { wrapperKey: string; expiresAt: number }>();
  /** An inner call allowed by a pre-decision completes the wrapper's receipt. */
  private readonly callAliases = new Map<string, string>();
  /** LumoAuth approvals that are being waited for (shown by status). */
  readonly pendingApprovals = new Set<PendingApproval>();
  private refreshTimer: NodeJS.Timeout | undefined;
  private statusTimer: NodeJS.Timeout | undefined;
  private usageTimer: NodeJS.Timeout | undefined;
  private started = false;
  private exitFlushTried = false;
  private exitHooks = false;
  private usageTokens = 0;
  private callCounter = 0;
  /** Set when server mode had to fall back to the snapshot (shown by status). */
  serverModeIssue: string | null = null;
  lastStatusWrite = 0;

  constructor(opts: GuardOptions) {
    this.opts = opts;
    this.home = opts.home;
    this.logger = opts.logger ?? silentLogger;
    this.contract = loadContract();
    this.now = opts.now ?? Date.now;
    this.snapshots = new SnapshotStore(() => this.loadState()?.client ?? null, this.now);
    this.receipts = new ReceiptQueue({
      send: async (calls) => {
        const st = this.loadState();
        if (!st) throw new LumoAuthError('client', 'LumoAuth Guard is not set up');
        await st.client.reportToolCalls(calls);
      },
      log: this.logger,
      now: this.now,
      spoolPath: join(this.home.dir, 'receipts-queue.jsonl'),
    });
  }

  // -------------------------------------------------------------------------
  // lifecycle

  /** Start background work (snapshot refresh, receipt flush, status file). Idempotent. */
  start(opts: { viaService?: boolean } = {}): void {
    if (this.started) return;
    this.started = true;
    // Receipts that an earlier process could not deliver (receipts-queue.jsonl).
    if (existsSync(this.home.dir)) this.receipts.claimSpool();
    this.receipts.start();
    // The gateway stops the service (stop() spools what is left); other
    // processes (openclaw agent --local) are short-lived and just exit.
    if (!opts.viaService) {
      this.exitHooks = true;
      process.on('beforeExit', this.onBeforeExit);
      process.on('exit', this.onExit);
    }
    const tick = () => {
      const st = this.loadState();
      if (st) void this.snapshots.refresh();
      this.scheduleRefresh();
    };
    tick();
    this.statusTimer = setInterval(() => this.writeStatusFile(), STATUS_WRITE_MS);
    this.statusTimer.unref?.();
    this.usageTimer = setInterval(() => void this.flushUsage(), USAGE_FLUSH_MS);
    this.usageTimer.unref?.();
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    const seconds = this.state?.config.refreshSeconds ?? 60;
    this.refreshTimer = setTimeout(() => {
      const st = this.loadState();
      if (st) void this.snapshots.refresh();
      this.scheduleRefresh();
    }, seconds * 1000);
    this.refreshTimer.unref?.();
  }

  /** Short-lived processes (openclaw agent --local): try once to deliver before exiting. */
  private readonly onBeforeExit = (): void => {
    if (this.exitFlushTried || this.receipts.size === 0 || !this.state) return;
    this.exitFlushTried = true;
    this.receipts.sweepPending();
    void this.receipts.flush(true);
  };

  /** At exit, keep what was not delivered for the next process. */
  private readonly onExit = (): void => {
    if (!this.state) return;
    this.receipts.spoolNow();
    this.writeStatusFile();
  };

  async stop(): Promise<void> {
    if (this.exitHooks) {
      process.off('beforeExit', this.onBeforeExit);
      process.off('exit', this.onExit);
      this.exitHooks = false;
    }
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    if (this.statusTimer) clearInterval(this.statusTimer);
    if (this.usageTimer) clearInterval(this.usageTimer);
    this.receipts.stop();
    this.started = false;
    this.receipts.sweepPending();
    await Promise.race([this.receipts.flush(true), new Promise((r) => setTimeout(r, 3000).unref?.())]);
    if (this.state) this.receipts.spoolNow();
    this.writeStatusFile();
  }

  // -------------------------------------------------------------------------
  // state

  private stamp(path: string): string {
    try {
      const s = statSync(path);
      return `${s.mtimeMs}:${s.size}:${s.ino}`;
    } catch {
      return 'missing';
    }
  }

  /** The config and client, reloaded when config.json or the key changes. Null when not set up. */
  loadState(): LoadedState | null {
    const stamp = `${this.stamp(this.home.configPath)}|${this.stamp(this.home.keyPath)}`;
    if (stamp === this.configStamp) return this.state;
    this.configStamp = stamp;
    const loaded = this.home.readConfig();
    if (!loaded.config) {
      this.state = null;
      this.stateError = loaded.exists ? loaded.error : undefined;
      this.snapshots.clear();
      return null;
    }
    if (!this.home.hasKey()) {
      this.state = null;
      this.stateError = 'agent-key.pem is missing';
      this.snapshots.clear();
      return null;
    }
    let key;
    try {
      key = this.home.readKey();
    } catch (err) {
      this.state = null;
      this.stateError = `agent-key.pem cannot be used: ${(err as Error).message}`;
      this.snapshots.clear();
      return null;
    }
    const c = loaded.config;
    const signature = [c.baseUrl, c.orgId, c.agentId, c.keyId, c.issuer, c.tokenEndpoint].join('|');
    const sameAgent = this.state?.signature === signature;
    const client = sameAgent
      ? this.state!.client
      : new AgentClient({
          baseUrl: c.baseUrl,
          orgId: c.orgId,
          agentId: c.agentId,
          issuer: c.issuer,
          tokenEndpoint: c.tokenEndpoint,
          keyId: c.keyId,
          key,
          fetchFn: this.opts.fetchFn,
          now: this.now,
          userAgent: `lumoauth-openclaw/${packageVersion()}`,
        });
    if (!sameAgent) {
      this.snapshots.clear();
      this.askCache.clear();
    }
    this.state = { config: c, issues: loaded.issues, client, signature };
    this.stateError = undefined;
    this.envCache.clear();
    if (this.started) this.scheduleRefresh();
    return this.state;
  }

  get setupError(): string | undefined {
    return this.stateError;
  }

  private hostPaths(config: OpenClawConfigLike | undefined): HostPaths {
    const env = this.opts.env ?? process.env;
    const paths = resolveHostPaths(env, config, this.opts.osHome);
    const fromHost = this.opts.stateDir?.();
    if (fromHost && fromHost !== paths.stateDir && !env.OPENCLAW_STATE_DIR) {
      return resolveHostPaths({ ...env, OPENCLAW_STATE_DIR: fromHost }, config, this.opts.osHome);
    }
    return paths;
  }

  private rulesFor(config: GuardConfig | null, agentId: string | undefined): { env: GuardEnv; rules: PathRules; shell: CompiledShellRules } {
    const hostConfig = this.opts.hostConfig?.();
    const sig = JSON.stringify([
      hostConfig?.agents?.defaults?.workspace,
      Array.isArray(hostConfig?.agents?.list) ? hostConfig.agents.list.map((a: any) => [a?.id, a?.workspace]) : null,
      config?.extraProtectedPaths,
      config?.allowPaths,
    ]);
    if (sig !== this.envSignature) {
      this.envCache.clear();
      this.envSignature = sig;
    }
    const key = agentId ?? '';
    const hit = this.envCache.get(key);
    if (hit) return hit;
    const env = buildGuardEnv({
      paths: this.hostPaths(hostConfig),
      config: hostConfig,
      agentId,
      guardHome: this.home.dir,
      pluginDir: this.opts.pluginDir ?? safePackageRoot(),
      extraProtectedPaths: config?.extraProtectedPaths ?? [],
      allowPaths: config?.allowPaths ?? [],
      ...(this.opts.platform ? { platform: this.opts.platform } : {}),
    });
    const rules = buildPathRules(env);
    const entry = { env, rules, shell: compileShellRules(rules, env) };
    if (this.envCache.size > 64) this.envCache.clear();
    this.envCache.set(key, entry);
    return entry;
  }

  // -------------------------------------------------------------------------
  // before_tool_call

  /** The before_tool_call hook. Never throws: an internal error blocks the call (fail closed). */
  async beforeToolCall(event: BeforeToolCallEvent, ctx: ToolHookContext = {}): Promise<BeforeToolCallResult | undefined> {
    try {
      return await this.evaluate(event, ctx);
    } catch (err) {
      this.logger.error(`LumoAuth Guard: internal error while checking ${safeToolName(event)}: ${(err as Error)?.message ?? err}`);
      return {
        block: true,
        blockReason: 'LumoAuth Guard could not check this call because of an internal error, so it was blocked to be safe. The owner can run `openclaw lumoauth doctor`.',
      };
    }
  }

  private async evaluate(event: BeforeToolCallEvent, ctx: ToolHookContext): Promise<BeforeToolCallResult | undefined> {
    if (!this.started) this.start();
    const nowMs = this.now();
    const toolName = typeof event?.toolName === 'string' && event.toolName ? event.toolName : String(ctx.toolName ?? 'unknown');
    const params = event?.params && typeof event.params === 'object' && !Array.isArray(event.params) ? event.params : {};
    const session = sessionKey(ctx, event);
    const callKey = this.callKey(event, ctx, toolName);
    const base: ReceiptBase = {
      tool: cut(toolName, 200),
      arguments_sha256: argumentsSha256(params),
      occurred_at: rfc3339(nowMs),
    };

    const st = this.loadState();
    // 1. Local lock.
    if (this.home.isLocked()) {
      return this.blocked(base, toolName, '-', { outcome: 'block', reason: 'locked', receiptDecision: 'blocked' });
    }
    // 2. Not set up.
    if (!st) {
      return this.blocked(base, toolName, '-', { outcome: 'block', reason: 'not_set_up', receiptDecision: 'blocked' });
    }
    const config = st.config;

    // Taint from the requester (§6.3): the session's last message came from someone other than the owner.
    if (config.taint.enabled && ctx.requester?.senderIsOwner === false) this.taint.mark(session, config.taint.windowSeconds, nowMs);
    const tainted = config.taint.enabled && this.taint.isTainted(session, nowMs);

    // Classification and hard rules.
    const { env, rules, shell } = this.rulesFor(config, ctx.agentId);
    const classified = classify(this.contract.host, this.contract.mcpVerbs, env, {
      toolName,
      params,
      derivedPaths: Array.isArray(event.derivedPaths) ? event.derivedPaths : undefined,
    });
    const c = classified.classification;
    if (c.server) base.server_id = c.server.slice(0, 100);
    // §4.1a: a dispatched call is decided as itself; its receipt names it.
    const decidedArgs = classified.dispatched?.args ?? params;
    const decidedTool = classified.dispatched ? classified.dispatched.rawName : toolName;
    if (classified.dispatched) {
      base.tool = cut(decidedTool, 200);
      base.arguments_sha256 = argumentsSha256(decidedArgs);
    }
    const hard = evaluateHardRules(classified, rules, shell, env, { tainted });

    // §4.1a: the host also runs a dispatched tool through this hook; the
    // wrapper's decision covers that one call (no second prompt or receipt).
    if (!c.dispatchedBy && hard.rule !== 'deny') {
      const wrapperKey = this.takePreDecision(session, c.tool, base.arguments_sha256!);
      if (wrapperKey) {
        this.callAliases.set(callKey, wrapperKey);
        if (this.callAliases.size > 1000) {
          const first = this.callAliases.keys().next().value;
          if (first !== undefined) this.callAliases.delete(first);
        }
        this.logger.debug?.(`LumoAuth Guard: ${cut(toolName, 80)} runs under the decision for its dispatch_action call`);
        return undefined;
      }
    }

    // 4. Snapshot (refreshed before the decision when older than refreshSeconds).
    // A cold start (no snapshot yet) may wait longer than a routine refresh.
    if (hard.rule !== 'deny') await this.snapshots.ensureFresh(config.refreshSeconds, this.snapshots.snapshot ? 5_000 : 10_000);
    let snapshot = this.snapshots.view();

    // 5. Server mode: the Ask API decides whether the capability is granted.
    let serverAllowed: boolean | undefined;
    let auditId: string | undefined;
    if (config.decisionMode === 'server' && hard.rule === null && snapshot && snapshot.status === 'active') {
      const r = await this.askServer(st, c.capability, c.tool, c.server);
      serverAllowed = r.allowed;
      auditId = r.auditId;
      snapshot = this.snapshots.view() ?? snapshot;
    }
    if (auditId && /^[0-9a-f]{16}$/.test(auditId)) base.audit_id = auditId;

    const decision = decide({
      classification: c,
      hardRule: hard.rule,
      state: { locked: false, setUp: true },
      snapshot,
      tainted,
      config,
      serverAllowed,
    });

    if (decision.outcome === 'block') {
      // With approvals off, say why approval was needed (the grant hint only helps for "not granted").
      const underlying =
        decision.reason === 'approvals_off'
          ? decide({ classification: c, hardRule: hard.rule, state: { locked: false, setUp: true }, snapshot, tainted, config: { ...config, approvals: 'host' }, serverAllowed }).reason
          : undefined;
      return this.blocked(base, decidedTool, c.capability, decision, { hard, classified, config, underlying });
    }

    if (decision.outcome === 'allow') {
      this.allowRan(base, callKey, decidedTool, c.capability, 'allowed', 'granted', classified, session, config);
      return undefined;
    }

    // 7. Approval. "Allow always" applies only to a capability that is not
    // granted (§6.4): hard-rule and taint approvals are asked every time.
    const hardApproval = decision.reason === 'hard_rule_approve';
    const rememberable = config.rememberApprovals && decision.reason === 'not_granted';
    if (rememberable && this.remembered.has(session, c.capability)) {
      this.allowRan(base, callKey, decidedTool, c.capability, 'approved', 'remembered', classified, session, config);
      return undefined;
    }

    const text = approvalText({
      classification: c,
      args: decidedArgs,
      commandArgs: classified.entry?.commandArgs,
      why: REASON_TEXT[decision.reason],
      hardRule: hardApproval,
    });

    let channel = this.channelFor(config);
    if (channel === 'lumoauth') {
      const push = await this.pushApproval(st, base, text, callKey, {
        classification: c,
        why: REASON_TEXT[decision.reason],
        args: approvalArgumentLines({ args: decidedArgs, commandArgs: classified.entry?.commandArgs }),
      });
      if (push.kind === 'approved') {
        this.allowRan(base, callKey, decidedTool, c.capability, 'approved', decision.reason, classified, session, config);
        return undefined;
      }
      if (push.kind === 'refused' || push.kind === 'expired') {
        const d: ToolCallReceipt['decision'] = push.kind === 'refused' ? 'refused' : 'expired';
        this.record({ ...base, decision: d, outcome: 'not_run', error_code: decision.reason }, decidedTool, c.capability, decision.reason);
        return {
          block: true,
          blockReason: this.blockText(
            push.kind === 'refused'
              ? 'The owner refused this call in LumoAuth.'
              : `No one answered the approval request in time (it was waiting ${push.where}).`,
            decision.reason,
            c.capability,
            config,
          ),
        };
      }
      // Unavailable: `auto` falls back to the host's approval UI for this call.
      if (config.approvals === 'auto') {
        this.logger.info(`LumoAuth Guard: LumoAuth approval unavailable (${push.code}); asking in OpenClaw instead.`);
        channel = 'host';
      } else {
        this.record({ ...base, decision: 'denied', outcome: 'not_run', error_code: `approval_${push.code}`.slice(0, 64) }, decidedTool, c.capability, decision.reason);
        return {
          block: true,
          blockReason: this.blockText(`${REASON_TEXT[decision.reason]}, and LumoAuth cannot ask the owner: ${push.text}.`, decision.reason, c.capability, config),
        };
      }
    }

    // Host approvals (§10.1): OpenClaw shows the request and resolves it.
    let resolved = false;
    return {
      requireApproval: {
        title: text.title,
        description: text.description,
        severity: text.severity,
        timeoutMs: HOST_APPROVAL_TIMEOUT_MS,
        timeoutReason: 'No one answered the LumoAuth Guard approval request in time.',
        allowedDecisions: rememberable ? ['allow-once', 'allow-always', 'deny'] : ['allow-once', 'deny'],
        pluginId: PLUGIN_ID,
        onResolution: (resolution: ApprovalResolution) => {
          if (resolved) return;
          resolved = true;
          try {
            if (resolution === 'allow-once' || resolution === 'allow-always') {
              if (resolution === 'allow-always' && rememberable) this.remembered.remember(session, c.capability);
              this.allowRan(base, callKey, decidedTool, c.capability, 'approved', decision.reason, classified, session, config);
            } else {
              const d = resolution === 'deny' ? 'refused' : 'expired';
              this.record({ ...base, decision: d, outcome: 'not_run', error_code: decision.reason }, decidedTool, c.capability, `${decision.reason}:${resolution}`);
            }
          } catch (err) {
            this.logger.error(`LumoAuth Guard: could not record an approval answer: ${(err as Error).message}`);
          }
        },
      },
    };
  }

  private channelFor(config: GuardConfig): 'lumoauth' | 'host' {
    if (config.approvals === 'lumoauth') return 'lumoauth';
    if (config.approvals === 'host') return 'host';
    return config.canActOnBehalfOfUsers && config.ownerUserId ? 'lumoauth' : 'host';
  }

  private callKey(event: BeforeToolCallEvent, ctx: ToolHookContext, toolName: string): string {
    const id = event?.toolCallId ?? ctx.toolCallId;
    if (typeof id === 'string' && id) return `id:${id}`;
    const key = `seq:${++this.callCounter}`;
    const fk = fallbackKey(event?.runId ?? ctx.runId, sessionKey(ctx, event), toolName);
    const list = this.pendingFallback.get(fk) ?? [];
    list.push(key);
    if (list.length > 50) list.shift();
    this.pendingFallback.set(fk, list);
    if (this.pendingFallback.size > 1000) {
      const first = this.pendingFallback.keys().next().value;
      if (first !== undefined) this.pendingFallback.delete(first);
    }
    return key;
  }

  /** The call will run: hold its receipt for after_tool_call, and taint the session after untrusted input. */
  private allowRan(
    base: ReceiptBase,
    callKey: string,
    toolName: string,
    capability: string,
    decision: 'allowed' | 'approved',
    reason: string,
    classified: ClassifyResult,
    session: string,
    config: GuardConfig,
  ): void {
    if (classified.classification.ingestsUntrusted && config.taint.enabled) {
      this.taint.mark(session, config.taint.windowSeconds, this.now());
    }
    this.pushRecent(toolName, capability, decision, reason);
    if (config.receipts) this.receipts.hold(callKey, { ...base, decision });
    if (classified.classification.dispatchedBy && base.arguments_sha256) {
      this.putPreDecision(session, classified.classification.tool, base.arguments_sha256, callKey);
    }
    this.logger.debug?.(`LumoAuth Guard: ${decision} ${toolName} (${capability})${classified.classification.dispatchedBy ? ` via ${classified.classification.dispatchedBy}` : ''}`);
  }

  private preDecisionKey(session: string, tool: string, digest: string): string {
    return `${session}\u0000${tool}\u0000${digest}`;
  }

  private putPreDecision(session: string, tool: string, digest: string, wrapperKey: string): void {
    const now = this.now();
    for (const [k, v] of this.preDecisions) if (v.expiresAt <= now) this.preDecisions.delete(k);
    this.preDecisions.set(this.preDecisionKey(session, tool, digest), { wrapperKey, expiresAt: now + PRE_DECISION_MS });
    while (this.preDecisions.size > 1000) {
      const first = this.preDecisions.keys().next().value;
      if (first === undefined) break;
      this.preDecisions.delete(first);
    }
  }

  /** A pre-decision is used once, within 60 s. */
  private takePreDecision(session: string, tool: string, digest: string): string | undefined {
    const k = this.preDecisionKey(session, tool, digest);
    const v = this.preDecisions.get(k);
    if (!v) return undefined;
    this.preDecisions.delete(k);
    return v.expiresAt > this.now() ? v.wrapperKey : undefined;
  }

  private record(receipt: ToolCallReceipt, toolName: string, capability: string, reason: string): void {
    this.pushRecent(toolName, capability, receipt.decision, reason);
    if (this.state?.config.receipts !== false && this.state) this.receipts.enqueue(receipt);
  }

  private pushRecent(tool: string, capability: string, decision: ToolCallReceipt['decision'], reason: string): void {
    this.recent.unshift({ at: rfc3339(this.now()), tool: cut(tool, 80), capability, decision, reason });
    if (this.recent.length > RECENT_MAX) this.recent.length = RECENT_MAX;
  }

  private blocked(
    base: ReceiptBase,
    toolName: string,
    capability: string,
    decision: Decision,
    extra?: BlockExtra,
  ): BeforeToolCallResult {
    const receiptDecision = decision.receiptDecision ?? 'blocked';
    this.record({ ...base, decision: receiptDecision, outcome: 'not_run', error_code: decision.reason }, toolName, capability, decision.reason);
    this.logger.info(`LumoAuth Guard: blocked ${cut(toolName, 80)} (${capability}): ${decision.reason}${extra?.hard.class ? ` [${extra.hard.class}]` : ''}`);
    return { block: true, blockReason: this.blockMessage(decision.reason, capability, extra) };
  }

  /** SPEC §6.1: the reason, and for steps 6/7 how the owner can grant it permanently. No capability list, key or token. */
  blockMessage(reason: ReasonCode, capability: string, extra?: BlockExtra): string {
    switch (reason) {
      case 'locked':
        return 'LumoAuth Guard blocked this call. Locked by the owner: run `openclaw lumoauth unlock`.';
      case 'not_set_up':
        return 'LumoAuth Guard blocked this call. LumoAuth Guard is not set up: run `openclaw lumoauth setup`.';
      case 'hard_rule':
        return `LumoAuth Guard blocked this call. ${REASON_TEXT.hard_rule}: ${classLabel(extra?.hard.class)}. Do not try another way to do this.`;
      case 'snapshot_unavailable': {
        const err = this.snapshots.lastError;
        const why = err?.kind === 'auth' ? ' (LumoAuth no longer accepts this agent\'s key)' : err ? ' (LumoAuth cannot be reached)' : '';
        return `LumoAuth Guard blocked this call. ${REASON_TEXT.snapshot_unavailable}${why}. The owner can run \`openclaw lumoauth status\`.`;
      }
      case 'agent_inactive':
        return `LumoAuth Guard blocked this call. ${REASON_TEXT.agent_inactive} (status: ${this.snapshots.snapshot?.status ?? 'unknown'}).`;
      case 'approvals_off': {
        const why = extra?.underlying && extra.underlying !== 'approvals_off' ? ` (${REASON_TEXT[extra.underlying].toLowerCase()})` : '';
        return this.blockText(`${REASON_TEXT.approvals_off}${why}.`, extra?.underlying ?? reason, capability, extra?.config ?? this.state?.config);
      }
      default:
        return this.blockText(`${REASON_TEXT[reason]}.`, reason, capability, extra?.config ?? this.state?.config);
    }
  }

  private blockText(text: string, reason: ReasonCode, capability: string, config: GuardConfig | undefined): string {
    let msg = `LumoAuth Guard blocked this call. ${text}`;
    if (reason === 'not_granted' && config) {
      msg += ` Ask the owner to add the capability \`${capability}\` to the agent in LumoAuth: ${agentPortalUrl(config)}`;
    }
    return msg;
  }

  // -------------------------------------------------------------------------
  // server mode

  private async askServer(st: LoadedState, capability: string, tool: string, server: string | null): Promise<{ allowed: boolean | undefined; auditId?: string }> {
    const cachedUntil = this.askCache.get(capability);
    if (cachedUntil && cachedUntil > this.now()) return { allowed: true };
    try {
      const r = await st.client.ask(capability, { tool, server, host: HOST });
      if (r.allowed) this.askCache.set(capability, this.now() + ASK_CACHE_MS);
      this.serverModeIssue = null;
      return { allowed: r.allowed, ...(r.auditId ? { auditId: r.auditId } : {}) };
    } catch (err) {
      const e = err as LumoAuthError;
      this.serverModeIssue =
        e?.code === 'plan_limit_reached'
          ? 'The Ask API limit of the plan is reached; the snapshot decides instead.'
          : `The Ask API could not be used (${e?.message ?? 'error'}); the snapshot decides instead.`;
      return { allowed: undefined };
    }
  }

  // -------------------------------------------------------------------------
  // LumoAuth push approvals (§7.5)

  private async pushApproval(
    st: LoadedState,
    base: ReceiptBase,
    text: { title: string; description: string; impact: string },
    callKey: string,
    info: { classification: { capability: string; risk: string; server: string | null }; why: string; args: string[] },
  ): Promise<PushOutcome> {
    const config = st.config;
    if (!config.canActOnBehalfOfUsers || !config.ownerUserId) {
      return { kind: 'unavailable', code: 'delegation_not_permitted', text: 'this agent may not ask the owner in LumoAuth (delegation is off)' };
    }
    // Poll until 10 s before OpenClaw ends the hook; ask LumoAuth to keep the request open as long (§7.5).
    const pollMs = Math.max(10_000, (this.opts.hookTimeoutMs?.() ?? DEFAULT_HOOK_TIMEOUT_MS) - 10_000);
    const deadline = this.now() + pollMs;
    const c = info.classification;
    let created;
    try {
      created = await st.client.createApproval({
        task_id: cut(`${HOST}-${callKey.startsWith('id:') ? callKey.slice(3) : randomBytes(8).toString('hex')}`, 128),
        reason: cut(text.description, 480),
        impact: text.impact,
        on_behalf_of: config.ownerUserId,
        expires_in: Math.min(600, Math.max(60, Math.round(pollMs / 1000))),
        meta: {
          kind: 'tool_call',
          host: HOST,
          tool: base.tool,
          ...(c.server ? { server: c.server } : {}),
          capability: c.capability,
          risk: c.risk,
          why: info.why,
          title: text.title,
          args: info.args,
          arguments_sha256: base.arguments_sha256 ?? '',
        },
      });
    } catch (err) {
      return { kind: 'unavailable', code: 'error', text: (err as Error).message };
    }
    if (created.kind === 'email_fallback_sent') return { kind: 'unavailable', code: 'email_fallback_sent', text: 'no approval channel reached the owner (an e-mail was sent instead)' };
    if (created.kind === 'no_enrolled_device') return { kind: 'unavailable', code: 'no_enrolled_device', text: 'the owner has no LumoAuth app enrolled and no approval channel is set up' };
    if (created.kind === 'delegation_not_permitted') return { kind: 'unavailable', code: 'delegation_not_permitted', text: 'this agent may not act on behalf of the owner' };
    const token = created.approvalToken!;
    const where = approvalWhere(created.delivery);
    const pending: PendingApproval = { since: rfc3339(this.now()), tool: cut(base.tool, 80), capability: c.capability, where };
    this.pendingApprovals.add(pending);
    this.logger.info(`LumoAuth Guard: waiting for approval ${where} (${pending.tool}, ${c.capability})`);
    this.writeStatusFile();
    try {
      const expiresAt = created.expiresAt ? Date.parse(created.expiresAt) : NaN;
      const stopAt = Number.isFinite(expiresAt) ? Math.min(deadline, expiresAt + 2_000) : deadline;
      const sleep = this.opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
      let errors = 0;
      while (this.now() < stopAt) {
        await sleep(PUSH_POLL_MS);
        try {
          const status = await st.client.approvalStatus(token);
          errors = 0;
          if (status === 'approved') return { kind: 'approved' };
          if (status === 'denied') return { kind: 'refused' };
          if (status === 'expired') return { kind: 'expired', where };
        } catch {
          if (++errors >= 5) return { kind: 'expired', where };
        }
      }
      return { kind: 'expired', where };
    } finally {
      this.pendingApprovals.delete(pending);
      this.writeStatusFile();
    }
  }

  // -------------------------------------------------------------------------
  // after_tool_call, usage

  /** The after_tool_call hook (fire-and-forget): completes the receipt. */
  afterToolCall(event: AfterToolCallEvent, ctx: ToolHookContext = {}): void {
    try {
      const id = event?.toolCallId ?? ctx.toolCallId;
      let key: string | undefined = typeof id === 'string' && id ? `id:${id}` : undefined;
      if (!key) {
        const fk = fallbackKey(event?.runId ?? ctx.runId, sessionKey(ctx, event as BeforeToolCallEvent), String(event?.toolName ?? ctx.toolName ?? ''));
        key = this.pendingFallback.get(fk)?.shift();
      }
      if (!key) return;
      // An inner call that ran under its dispatch_action decision completes that receipt.
      const alias = this.callAliases.get(key);
      if (alias) {
        this.callAliases.delete(key);
        key = alias;
      }
      const fields: Partial<ToolCallReceipt> = { outcome: event?.error ? 'failed' : 'succeeded' };
      if (typeof event?.durationMs === 'number' && Number.isFinite(event.durationMs)) {
        fields.duration_ms = Math.max(0, Math.min(86_400_000, Math.round(event.durationMs)));
      }
      if (event?.error) fields.error_code = 'tool_error';
      this.receipts.complete(key, fields);
    } catch (err) {
      this.logger.warn(`LumoAuth Guard: after_tool_call: ${(err as Error).message}`);
    }
  }

  /** llm_output (only registered when conversation access is allowed): model tokens for §7.6. */
  onLlmOutput(event: LlmOutputEvent): void {
    const total = event?.usage?.total;
    if (typeof total === 'number' && Number.isFinite(total) && total > 0) this.usageTokens += Math.round(total);
  }

  async flushUsage(): Promise<void> {
    if (this.usageTokens <= 0) return;
    const st = this.loadState();
    if (!st) return;
    const tokens = Math.min(this.usageTokens, 100_000_000);
    this.usageTokens -= tokens;
    try {
      await st.client.reportUsage(tokens);
    } catch (err) {
      if ((err as LumoAuthError).transient) this.usageTokens += tokens;
    }
  }

  // -------------------------------------------------------------------------
  // status

  statusSummary(): Record<string, unknown> {
    const st = this.state;
    const snap = this.snapshots.snapshot;
    return {
      updatedAt: rfc3339(this.now()),
      pid: process.pid,
      setUp: st !== null,
      setupError: this.stateError ?? null,
      locked: this.home.readLock(),
      agentId: st?.config.agentId ?? null,
      snapshot: snap
        ? { status: snap.status, fetchedAt: rfc3339(snap.fetchedAtMs), capabilities: snap.capabilities.length }
        : null,
      lastError: this.snapshots.lastError ? { at: rfc3339(this.snapshots.lastError.atMs), kind: this.snapshots.lastError.kind, message: this.snapshots.lastError.message } : null,
      serverModeIssue: this.serverModeIssue,
      receipts: this.receipts.snapshot(),
      taintedSessions: this.taint.taintedSessions(this.now()),
      waitingForApproval: [...this.pendingApprovals].map((p) => ({ ...p, text: `Waiting for approval ${p.where}` })),
      rememberedApprovals: this.remembered.size,
      recent: this.recent.slice(0, RECENT_MAX),
    };
  }

  writeStatusFile(): void {
    if (!this.state) return;
    try {
      this.home.writeSecure(this.home.statusPath, `${JSON.stringify(this.statusSummary(), null, 2)}\n`);
      this.lastStatusWrite = this.now();
    } catch {
      // Best effort: status is informational.
    }
  }
}

function safePackageRoot(): string | undefined {
  try {
    return packageRoot();
  } catch {
    return undefined;
  }
}

function safeToolName(event: BeforeToolCallEvent | undefined): string {
  return typeof event?.toolName === 'string' ? cut(event.toolName, 80) : 'a tool call';
}

export function sessionKey(ctx: ToolHookContext | undefined, event?: { runId?: string } | undefined): string {
  return ctx?.sessionKey || ctx?.sessionId || (ctx?.runId ? `run:${ctx.runId}` : event?.runId ? `run:${event.runId}` : 'global');
}

function fallbackKey(runId: string | undefined, session: string, toolName: string): string {
  return `${runId ?? session}\u0000${toolName}`;
}

/** RFC 3339 UTC with seconds precision (what the receipt endpoint documents). */
export function rfc3339(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');
}

export function classLabel(cls: string | undefined): string {
  switch (cls) {
    case 'guard':
      return "the Guard's own files";
    case 'hostConfig':
      return "OpenClaw's configuration, credentials or plugin files";
    case 'hostSkills':
      return "OpenClaw's installed skills (only the owner changes them)";
    case 'hostState':
      return "OpenClaw's internal state";
    case 'secrets':
      return 'a credential store (SSH, cloud, registry or browser secrets)';
    case 'secretFile':
      return 'a secret file (.env, key or certificate)';
    case 'persistence':
      return 'a shell start-up file or an autostart entry';
    case 'command':
      return 'an OpenClaw admin command, a change to OpenClaw or its plugins, or stopping OpenClaw';
    case 'tool':
      return 'managing OpenClaw plugins or the gateway';
    default:
      return 'a protected resource';
  }
}
