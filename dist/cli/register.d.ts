import type { GuardHome } from '../guard-home.ts';
import type { HostPaths } from '../host/host-env.ts';
import type { CliContext, OpenClawConfigLike } from '../host/openclaw-types.ts';
import { type HostConfigWriter } from './commands.ts';
import { type CliIo } from './io.ts';
export declare const CLI_DESCRIPTOR: {
    name: string;
    description: string;
    hasSubcommands: boolean;
};
export interface CliBindings {
    home: () => GuardHome;
    paths: (config: OpenClawConfigLike | undefined) => HostPaths;
    /** The host's config writer, looked up when a command runs (never during registration). */
    configWriter: () => HostConfigWriter | undefined;
    io?: () => CliIo;
}
/** `openclaw lumoauth setup|status|doctor|lock|unlock|reset` (SPEC §2, §8, §9). */
export declare function registerLumoauthCli(ctx: CliContext, bindings: CliBindings): void;
