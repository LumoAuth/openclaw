/**
 * The machine that the rules are evaluated against (SPEC §4.4, §5.1). Built
 * from the real environment by host/env.ts; tests inject
 * contract/vectors/environment.json.
 */
export interface GuardEnv {
    home: string;
    /** OpenClaw state dir: $OPENCLAW_STATE_DIR, else ~/.openclaw (or ~/.openclaw-<profile>). */
    stateDir: string;
    /** $OPENCLAW_CONFIG_PATH when set (also protected); the default config file is in stateDir. */
    configPathFromEnv?: string | undefined;
    /** Workspace that relative file paths resolve against. */
    workspace: string;
    /** Every configured workspace (excepted from the hostState rule). */
    workspaces: string[];
    /** Default working directory of shell tools. */
    cwd: string;
    /** Guard home ($LUMOAUTH_GUARD_HOME or ~/.lumoauth/guard/openclaw). */
    guardHome: string;
    /** This plugin's install directory (protected as hostConfig). */
    pluginDir?: string | undefined;
    platform: NodeJS.Platform | string;
    extraProtectedPaths: string[];
    allowPaths: string[];
    /**
     * Resolve symlinks. Returns undefined when nothing on the path exists. The
     * default (host/env.ts) resolves the deepest existing ancestor and appends
     * the rest, so a symlinked parent directory is followed too.
     */
    realpath?: ((path: string) => string | undefined) | undefined;
    /**
     * Real (symlink-resolved) forms of the state dir and of `~/.lumoauth`,
     * when they differ: their rules are added for these forms too.
     */
    aliases?: {
        stateDir?: string | undefined;
        lumoauthRoot?: string | undefined;
    } | undefined;
}
export type PathClass = 'guard' | 'hostConfig' | 'hostSkills' | 'hostState' | 'secrets' | 'secretFile' | 'persistence';
export declare function isCaseInsensitive(platform: string): boolean;
/** Use '/' everywhere so one set of patterns works on every platform. */
export declare function toSlashes(p: string): string;
/** Expand `~`, `~/…`, `$HOME` and `${HOME}`. */
export declare function expandHome(p: string, home: string): string;
/** Absolute, lexically normalised form of `p` (relative paths resolve against `base`). */
export declare function resolvePath(p: string, base: string, env: Pick<GuardEnv, 'home' | 'platform'>): string;
/**
 * Compile a path pattern: `<dir>/**` matches the directory and everything
 * below it; `*` matches within one segment (so `openclaw.json*` also covers
 * `openclaw.json.bak`).
 */
export declare function compilePattern(pattern: string, caseInsensitive: boolean): RegExp;
/** The literal part of a pattern before its first wildcard (for substring scans). */
export declare function patternRoot(pattern: string): {
    root: string;
    isDir: boolean;
    prefixFile: boolean;
};
export interface PathRules {
    caseInsensitive: boolean;
    classes: {
        cls: Exclude<PathClass, 'secretFile'>;
        patterns: string[];
        regexes: RegExp[];
    }[];
    hostStateExceptions: RegExp[];
    /** Patterns of the classes that a shell substring scan looks for (guard, hostConfig, secrets). */
    substringPatterns: {
        cls: PathClass;
        pattern: string;
    }[];
}
/** Build the §5.1 path rules for OpenClaw from the environment. */
export declare function buildPathRules(env: GuardEnv): PathRules;
/** SPEC §5.1 `secretFile`: `.env`, `.env.*` (not the example files), `*.pem`, `*.key`, SSH private key names. */
export declare function isSecretFileName(name: string, caseInsensitive: boolean): boolean;
/** The first §5.1 class that matches an absolute path, in the table's order. */
export declare function classifyPath(rules: PathRules, absPath: string): PathClass | null;
