import type { ClassifyResult } from './classify.ts';
import { type GuardEnv, type PathClass, type PathRules } from './paths.ts';
export type RuleLevel = 'deny' | 'approve' | null;
export type HardRuleClass = PathClass | 'command' | 'tool';
export interface HardRuleResult {
    rule: RuleLevel;
    class?: HardRuleClass | undefined;
    /** Which pattern matched, for logs and block messages (never an argument value). */
    detail?: string | undefined;
}
declare class Strictest {
    result: HardRuleResult;
    offer(rule: RuleLevel, cls: HardRuleClass, detail?: string): void;
    get denied(): boolean;
}
/** Expand `$HOME`, `${HOME}` everywhere and `~` at the start of a word. */
export declare function expandShellHome(text: string, home: string): string;
export interface CompiledShellRules {
    substrings: {
        cls: PathClass;
        re: RegExp;
    }[];
}
/**
 * Substring scans (§5.3): the absolute form of every guard, hostConfig and
 * secrets pattern. Also the home-relative form of the guard and hostConfig
 * patterns (`.lumoauth/…`, `.openclaw/openclaw.json`), which catches
 * `cd ~ && cat .openclaw/openclaw.json`.
 */
export declare function compileShellRules(rules: PathRules, env: GuardEnv): CompiledShellRules;
/** §5.3: scan one shell command or piece of code. */
export declare function scanCommand(text: string, workdir: string, rules: PathRules, shell: CompiledShellRules, env: GuardEnv, tainted: boolean, out?: Strictest): HardRuleResult;
/** SPEC §5: every hard rule for one classified call. */
export declare function evaluateHardRules(classified: ClassifyResult, rules: PathRules, shell: CompiledShellRules, env: GuardEnv, opts: {
    tainted: boolean;
}): HardRuleResult;
export {};
