import { Guard } from './guard.ts';
import type { CommandContext, OpenClawPluginApiLike } from './host/openclaw-types.ts';
/** SPEC §10.1: the lowest priority, so the Guard judges the parameters that the tool really gets. */
export declare const HOOK_PRIORITY = -1000;
/** The Guard of this process (created on first use). */
export declare function getGuard(api: OpenClawPluginApiLike, overrides?: Partial<ConstructorParameters<typeof Guard>[0]>): Guard;
/** Reset the process-wide Guard (tests). */
export declare function resetGuardForTests(): Promise<void>;
export declare function register(api: OpenClawPluginApiLike, overrides?: Partial<ConstructorParameters<typeof Guard>[0]>): void;
/** `/lumoauth` in chat: status (default) and lock. Unlock is terminal-only. */
export declare function chatCommand(guard: Guard, ctx: CommandContext): {
    text: string;
};
