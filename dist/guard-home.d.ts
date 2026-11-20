import { type GuardConfig, type LoadedConfig } from './config.ts';
import type { KeyObject } from 'node:crypto';
/** SPEC §3: `$LUMOAUTH_GUARD_HOME`, else `~/.lumoauth/guard/openclaw`. */
export declare function resolveGuardHome(env?: NodeJS.ProcessEnv, home?: string): string;
export declare const IS_POSIX: boolean;
/** The files of the Guard home. */
export declare class GuardHome {
    readonly dir: string;
    constructor(dir: string);
    get configPath(): string;
    get keyPath(): string;
    get lockPath(): string;
    /** Written by the gateway process so that `status` (another process) can show recent decisions and the receipt queue. */
    get statusPath(): string;
    /** Create the directory with mode 0700 (and tighten it when it exists). */
    ensure(): void;
    /** Write a file with mode 0600, atomically (temp file + rename). */
    writeSecure(path: string, content: string): void;
    readConfig(): LoadedConfig & {
        exists: boolean;
    };
    writeConfig(config: GuardConfig): void;
    hasKey(): boolean;
    readKey(): KeyObject;
    writeKey(pem: string): void;
    readLock(): {
        at: string;
        reason: string;
    } | null;
    isLocked(): boolean;
    lock(reason: string, now?: Date): void;
    unlock(): boolean;
    /** The last report written by a running Guard (status.json), or null. */
    readStatusReport(): Record<string, any> | null;
    /** Mode bits of a file (POSIX), or undefined. */
    mode(path: string): number | undefined;
}
