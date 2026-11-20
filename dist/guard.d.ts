import { type ClassifyResult } from './core/classify.ts';
import { type ReasonCode } from './core/decide.ts';
import { type HardRuleResult } from './core/hard-rules.ts';
import { RememberedApprovals, TaintTracker } from './core/session-memory.ts';
import { type GuardConfig } from './config.ts';
import { GuardHome } from './guard-home.ts';
import type { AfterToolCallEvent, BeforeToolCallEvent, BeforeToolCallResult, LlmOutputEvent, OpenClawConfigLike, PluginLogger, ToolHookContext } from './host/openclaw-types.ts';
import { AgentClient, type ToolCallReceipt } from './lumoauth/agent-client.ts';
import type { FetchFn } from './lumoauth/http.ts';
import { ReceiptQueue } from './lumoauth/receipts.ts';
import { SnapshotStore } from './lumoauth/snapshot.ts';
export declare const HOST = "openclaw";
export declare const PLUGIN_ID = "lumoauth";
/** Hook timeout that this plugin registers with (OpenClaw's default for before_tool_call is 15 s). */
export declare const DEFAULT_HOOK_TIMEOUT_MS = 180000;
/** Approval wait for the host's approval UI (SPEC §10.1). */
export declare const HOST_APPROVAL_TIMEOUT_MS = 120000;
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
/** Where a LumoAuth approval can be answered, from the server's `delivery` list (§7.5). */
export declare function approvalWhere(delivery: string[] | undefined): string;
export interface PendingApproval {
    since: string;
    tool: string;
    capability: string;
    where: string;
}
interface BlockExtra {
    hard: HardRuleResult;
    classified: ClassifyResult;
    config: GuardConfig;
    /** For approvals_off: why approval was needed. */
    underlying?: ReasonCode | undefined;
}
/**
 * LumoAuth Guard for one OpenClaw process: classifies each tool call,
 * applies the hard rules and the decision order (SPEC §5, §6), asks for
 * approvals, and reports receipts.
 */
export declare class Guard {
    readonly home: GuardHome;
    readonly taint: TaintTracker;
    readonly remembered: RememberedApprovals;
    readonly snapshots: SnapshotStore;
    readonly receipts: ReceiptQueue;
    readonly recent: RecentDecision[];
    private readonly opts;
    private readonly logger;
    private readonly contract;
    private readonly now;
    private state;
    private stateError;
    private configStamp;
    private envCache;
    private envSignature;
    private readonly askCache;
    private readonly pendingFallback;
    /** §4.1a pre-decisions: (session, dispatched tool, argument digest) → the wrapper's receipt key. */
    private readonly preDecisions;
    /** An inner call allowed by a pre-decision completes the wrapper's receipt. */
    private readonly callAliases;
    /** LumoAuth approvals that are being waited for (shown by status). */
    readonly pendingApprovals: Set<PendingApproval>;
    private refreshTimer;
    private statusTimer;
    private usageTimer;
    private started;
    private exitFlushTried;
    private exitHooks;
    private usageTokens;
    private callCounter;
    /** Set when server mode had to fall back to the snapshot (shown by status). */
    serverModeIssue: string | null;
    lastStatusWrite: number;
    constructor(opts: GuardOptions);
    /** Start background work (snapshot refresh, receipt flush, status file). Idempotent. */
    start(opts?: {
        viaService?: boolean;
    }): void;
    private scheduleRefresh;
    /** Short-lived processes (openclaw agent --local): try once to deliver before exiting. */
    private readonly onBeforeExit;
    /** At exit, keep what was not delivered for the next process. */
    private readonly onExit;
    stop(): Promise<void>;
    private stamp;
    /** The config and client, reloaded when config.json or the key changes. Null when not set up. */
    loadState(): LoadedState | null;
    get setupError(): string | undefined;
    private hostPaths;
    private rulesFor;
    /** The before_tool_call hook. Never throws: an internal error blocks the call (fail closed). */
    beforeToolCall(event: BeforeToolCallEvent, ctx?: ToolHookContext): Promise<BeforeToolCallResult | undefined>;
    private evaluate;
    private channelFor;
    private callKey;
    /** The call will run: hold its receipt for after_tool_call, and taint the session after untrusted input. */
    private allowRan;
    private preDecisionKey;
    private putPreDecision;
    /** A pre-decision is used once, within 60 s. */
    private takePreDecision;
    private record;
    private pushRecent;
    private blocked;
    /** SPEC §6.1: the reason, and for steps 6/7 how the owner can grant it permanently. No capability list, key or token. */
    blockMessage(reason: ReasonCode, capability: string, extra?: BlockExtra): string;
    private blockText;
    private askServer;
    private pushApproval;
    /** The after_tool_call hook (fire-and-forget): completes the receipt. */
    afterToolCall(event: AfterToolCallEvent, ctx?: ToolHookContext): void;
    /** llm_output (only registered when conversation access is allowed): model tokens for §7.6. */
    onLlmOutput(event: LlmOutputEvent): void;
    flushUsage(): Promise<void>;
    statusSummary(): Record<string, unknown>;
    writeStatusFile(): void;
}
export declare function sessionKey(ctx: ToolHookContext | undefined, event?: {
    runId?: string;
} | undefined): string;
/** RFC 3339 UTC with seconds precision (what the receipt endpoint documents). */
export declare function rfc3339(ms: number): string;
export declare function classLabel(cls: string | undefined): string;
export {};
