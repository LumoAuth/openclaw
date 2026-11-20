/**
 * The parts of OpenClaw's plugin API that this plugin uses (OpenClaw
 * 2026.11.5: src/plugins/plugin-api.types.ts, hook-types.ts,
 * hook-before-tool-call-result.ts, plugin-command.types.ts,
 * plugin-registration.types.ts). Declared here structurally so that the
 * package has no runtime or build dependency on a specific OpenClaw build.
 */
export interface PluginLogger {
    debug?: (message: string) => void;
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
}
/** OpenClaw's config object (openclaw.json), read structurally. */
export type OpenClawConfigLike = Record<string, any>;
export type PluginRegistrationMode = 'full' | 'discovery' | 'tool-discovery' | 'setup-only' | 'setup-runtime' | 'cli-metadata';
export interface BeforeToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    toolKind?: string;
    runId?: string;
    toolCallId?: string;
    derivedPaths?: readonly string[];
}
export interface ToolHookContext {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
    toolName?: string;
    toolCallId?: string;
    channelId?: string;
    requester?: {
        channel?: string;
        accountId?: string;
        senderId?: string;
        senderIsOwner?: boolean;
    };
    trigger?: string;
}
export interface AfterToolCallEvent {
    toolName: string;
    params: Record<string, unknown>;
    runId?: string;
    toolCallId?: string;
    result?: unknown;
    error?: string;
    durationMs?: number;
}
export type ApprovalResolution = 'allow-once' | 'allow-always' | 'deny' | 'timeout' | 'cancelled';
export interface BeforeToolCallResult {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
    requireApproval?: {
        title: string;
        description: string;
        severity?: 'info' | 'warning' | 'critical';
        timeoutMs?: number;
        timeoutReason?: string;
        allowedDecisions?: Array<'allow-once' | 'allow-always' | 'deny'>;
        pluginId?: string;
        onResolution?: (decision: ApprovalResolution) => Promise<void> | void;
    };
}
export interface LlmOutputEvent {
    runId?: string;
    sessionId?: string;
    usage?: {
        input?: number;
        output?: number;
        cacheRead?: number;
        cacheWrite?: number;
        total?: number;
    };
}
export interface CommandContext {
    senderId?: string;
    channel?: string;
    isAuthorizedSender?: boolean;
    senderIsOwner?: boolean;
    args?: string;
    commandBody?: string;
    config?: OpenClawConfigLike;
}
export interface CommandDefinition {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    requiredScopes?: string[];
    handler: (ctx: CommandContext) => {
        text: string;
    } | Promise<{
        text: string;
    }>;
}
export interface CliContext {
    program: CommanderLike;
    config: OpenClawConfigLike;
    workspaceDir?: string;
    logger: PluginLogger;
}
/** The subset of commander's Command used here. */
export interface CommanderLike {
    command(name: string): CommanderLike;
    description(text: string): CommanderLike;
    option(flags: string, description?: string, defaultValue?: unknown): CommanderLike;
    argument(name: string, description?: string): CommanderLike;
    action(fn: (...args: any[]) => unknown): CommanderLike;
    helpOption?: (...args: any[]) => CommanderLike;
}
export interface SecurityAuditContext {
    config: OpenClawConfigLike;
    sourceConfig?: OpenClawConfigLike;
    env: NodeJS.ProcessEnv;
    stateDir: string;
    configPath: string;
}
export interface SecurityAuditFinding {
    checkId: string;
    severity: 'info' | 'warn' | 'critical';
    title: string;
    detail: string;
    remediation?: string;
}
export interface ServiceContext {
    config?: OpenClawConfigLike;
    stateDir?: string;
    logger?: PluginLogger;
}
export interface ConfigMutationParams {
    afterWrite: {
        mode: 'auto';
    } | {
        mode: 'restart';
        reason: string;
    } | {
        mode: 'none';
        reason: string;
    };
    mutate: (draft: OpenClawConfigLike) => void | Promise<void>;
}
export interface PluginRuntimeLike {
    config?: {
        current?: () => OpenClawConfigLike;
        mutateConfigFile?: (params: ConfigMutationParams) => Promise<unknown>;
    };
    state?: {
        resolveStateDir?: () => string;
    };
}
export interface OpenClawPluginApiLike {
    id?: string;
    registrationMode?: PluginRegistrationMode | string;
    config?: OpenClawConfigLike;
    pluginConfig?: Record<string, unknown>;
    runtime?: PluginRuntimeLike;
    rootDir?: string;
    logger?: PluginLogger;
    on?: (hookName: string, handler: (...args: any[]) => any, opts?: {
        priority?: number;
        timeoutMs?: number;
    }) => void;
    registerCli?: (registrar: (ctx: CliContext) => void | Promise<void>, opts?: {
        descriptors?: {
            name: string;
            description: string;
            hasSubcommands: boolean;
        }[];
    }) => void;
    registerCommand?: (command: CommandDefinition) => void;
    registerService?: (service: {
        id: string;
        start: (ctx: ServiceContext) => void | Promise<void>;
        stop?: (ctx: ServiceContext) => void | Promise<void>;
    }) => void;
    registerSecurityAuditCollector?: (collector: (ctx: SecurityAuditContext) => SecurityAuditFinding[] | Promise<SecurityAuditFinding[]>) => void;
}
