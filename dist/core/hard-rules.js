import { classifyPath, isSecretFileName, resolvePath, toSlashes, } from "./paths.js";
/** SPEC §5.1: the outcome per class and column. */
const COLUMNS = {
    guard: { read: 'deny', write: 'deny', shell: 'deny' },
    hostConfig: { read: 'deny', write: 'deny', shell: 'deny' },
    hostSkills: { read: null, write: 'deny', shell: 'approve' },
    hostState: { read: 'deny', write: 'deny', shell: 'approve' },
    secrets: { read: 'deny', write: 'deny', shell: 'deny' },
    secretFile: { read: 'approve', write: 'approve', shell: 'approve' },
    persistence: { read: null, write: 'approve', shell: 'approve' },
};
const RANK = { deny: 2, approve: 1, null: 0 };
class Strictest {
    result = { rule: null };
    offer(rule, cls, detail) {
        if (rule === null)
            return;
        if (RANK[rule] > RANK[String(this.result.rule)])
            this.result = { rule, class: cls, detail };
    }
    get denied() {
        return this.result.rule === 'deny';
    }
}
/** At most this many path-like shell tokens get the (file system) symlink check. */
const MAX_REALPATH_TOKENS = 500;
const SHELL_SPLIT = /[\s;|&<>()'"`=]+/;
const PATH_CHAR = 'A-Za-z0-9._-';
function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
/** Expand `$HOME`, `${HOME}` everywhere and `~` at the start of a word. */
export function expandShellHome(text, home) {
    return text
        .replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home)
        .replace(/(^|[\s;|&<>()'"`=:,])~(?=$|[/\s;|&<>()'"`,])/g, `$1${home}`);
}
/** Unanchored regex for a protected pattern inside free text (shell or code). */
function substringRegex(pattern, caseInsensitive) {
    let p = toSlashes(pattern);
    let tail = `(?![${PATH_CHAR}])`;
    if (p.endsWith('/**'))
        p = p.slice(0, -3);
    else if (p.endsWith('*') && !p.slice(0, -1).includes('*')) {
        p = p.slice(0, -1);
        tail = '';
    }
    const body = p
        .split('*')
        .map(escapeRegex)
        .join(`[^/\\s'"\`;|&<>()=]*`);
    return new RegExp(`(?<![${PATH_CHAR}])${body}${tail}`, caseInsensitive ? 'i' : '');
}
/**
 * Substring scans (§5.3): the absolute form of every guard, hostConfig and
 * secrets pattern. Also the home-relative form of the guard and hostConfig
 * patterns (`.lumoauth/…`, `.openclaw/openclaw.json`), which catches
 * `cd ~ && cat .openclaw/openclaw.json`.
 */
export function compileShellRules(rules, env) {
    const home = toSlashes(env.home).replace(/\/+$/, '');
    const out = [];
    for (const { cls, pattern } of rules.substringPatterns) {
        out.push({ cls, re: substringRegex(pattern, rules.caseInsensitive) });
        if ((cls === 'guard' || cls === 'hostConfig') && pattern.startsWith(`${home}/.`)) {
            out.push({ cls, re: substringRegex(pattern.slice(home.length + 1), rules.caseInsensitive) });
        }
    }
    return { substrings: out };
}
function pathRuleFor(rules, env, abs, column, useRealpath) {
    let best = { rule: null, cls: null };
    const forms = [abs];
    if (useRealpath && env.realpath) {
        const real = env.realpath(abs);
        if (real && real !== abs)
            forms.push(toSlashes(real));
    }
    for (const form of forms) {
        const cls = classifyPath(rules, form);
        if (!cls)
            continue;
        const rule = COLUMNS[cls][column];
        if (RANK[String(rule)] > RANK[String(best.rule)])
            best = { rule, cls };
        else if (best.cls === null)
            best = { rule, cls };
    }
    return best;
}
// ---------------------------------------------------------------------------
// §5.3 command patterns
const OPENCLAW_DENY_SUBCOMMANDS = new Set(['plugins', 'plugin', 'config', 'lumoauth', 'hooks', 'security', 'update']);
const HERMES_DENY_SUBCOMMANDS = new Set(['plugins', 'plugin', 'config', 'lumoauth', 'setup', 'update', 'hooks']);
const GATEWAY_DENY = new Set(['stop', 'restart', 'install', 'uninstall']);
const NODE_PMS = new Set(['npm', 'pnpm', 'yarn', 'bun']);
const NODE_PM_VERBS = new Set(['install', 'i', 'add', 'uninstall', 'remove', 'rm', 'r', 'un', 'unlink', 'update', 'up', 'upgrade', 'link', 'ln']);
const NODE_PROTECTED = new Set(['openclaw', '@lumoauth/openclaw']);
const PY_VERBS = new Set(['install', 'uninstall', 'upgrade', 'reinstall']);
const PY_PROTECTED = new Set(['hermes-agent', 'lumoauth-hermes']);
const SERVICE_VERBS = new Set(['stop', 'disable', 'unload', 'bootout', 'kill', 'mask', 'remove']);
const PROTECTED_ENV = ['HERMES_SAFE_MODE', 'OPENCLAW_CONFIG_PATH', 'OPENCLAW_STATE_DIR', 'LUMOAUTH_GUARD_HOME', 'HERMES_HOME', 'OPENCLAW_PROFILE', 'OPENCLAW_HOME'];
const COMMAND_PREFIXES = new Set(['sudo', 'doas', 'env', 'nohup', 'time', 'command', 'exec', 'nice', 'ionice', 'builtin', 'xargs', 'timeout', 'stdbuf']);
const ENV_SET_RE = new RegExp(`(?<![A-Za-z0-9_$])(?:${PROTECTED_ENV.join('|')})(?:\\s*=(?!=)|['"]\\s*\\]\\s*=(?!=))` +
    `|(?:setenv|putenv|setdefault|set\\s+-[A-Za-z]*x[A-Za-z]*)\\s*\\(?\\s*['"]?(?:${PROTECTED_ENV.join('|')})(?![A-Za-z0-9_])`);
const ENVIRON_RE = /\/proc\/[^/\s]+\/environ/;
const PIPE_TO_SHELL_RE = /\|\s*(?:(?:sudo|doas|env|exec)\s+(?:-\S+\s+)*)?(?:\S*\/)?(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|node|perl|ruby|php)(?![A-Za-z0-9_.-])/;
const PROCESS_SUBST_SHELL_RE = /(?<![A-Za-z0-9_.-])(?:sh|bash|zsh|source|\.)\s+<\(/;
const DECODE_RE = /(?<![A-Za-z0-9_-])(?:base64\s+(?:\S+\s+)*?(?:-d|--decode|-D)(?![A-Za-z0-9_-])|xxd\s+(?:\S+\s+)*?-r(?:p)?(?![A-Za-z0-9_-]))/;
const RUNNER_RE = /(?<![A-Za-z0-9_.-])(?:sh|bash|eval|exec)(?![A-Za-z0-9_.-])/;
function baseWord(w) {
    const s = w.replace(/\\/g, '/');
    return s.slice(s.lastIndexOf('/') + 1);
}
/** Simple commands of a shell text: split at ; & | ( ) ` $( and newlines; words split at blanks and quotes. */
function segments(text) {
    return text
        .split(/\$\(|[;&|()`\n\r]+/)
        .map((seg) => seg.split(/[\s'"<>]+/).filter((w) => w !== ''))
        .filter((words) => words.length > 0);
}
function packageName(word) {
    const w = word.replace(/^npm:/, '');
    if (w.startsWith('@')) {
        const at = w.indexOf('@', 1);
        return (at === -1 ? w : w.slice(0, at)).toLowerCase();
    }
    const at = w.indexOf('@');
    return (at === -1 ? w : w.slice(0, at)).toLowerCase();
}
function pyPackageName(word) {
    return word.split(/[=<>!~[;@\s]/)[0].toLowerCase().replace(/_/g, '-');
}
/** The command word of a simple command: skip assignments and prefixes such as sudo/env. */
function commandWord(words) {
    let i = 0;
    while (i < words.length) {
        const w = words[i];
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) {
            i++;
            continue;
        }
        const b = baseWord(w);
        if (COMMAND_PREFIXES.has(b)) {
            i++;
            while (i < words.length && words[i].startsWith('-'))
                i++;
            continue;
        }
        return b;
    }
    return undefined;
}
function commandPatterns(text, tainted, out) {
    if (ENV_SET_RE.test(text))
        out.offer('deny', 'command', 'sets a protected environment variable');
    for (const words of segments(text)) {
        const bases = words.map(baseWord);
        for (let i = 0; i < bases.length; i++) {
            const b = bases[i];
            if (b === 'openclaw' || b === 'openclaw.mjs' || b === 'hermes') {
                const rest = words.slice(i + 1);
                if (rest.includes('--safe-mode'))
                    out.offer('deny', 'command', `${b} --safe-mode`);
                const nonDash = rest.filter((w) => !w.startsWith('-'));
                const deny = b === 'hermes' ? HERMES_DENY_SUBCOMMANDS : OPENCLAW_DENY_SUBCOMMANDS;
                for (let k = 0; k < Math.min(3, nonDash.length); k++) {
                    const sub = nonDash[k];
                    if (deny.has(sub))
                        out.offer('deny', 'command', `${b} ${sub}`);
                    if (b !== 'hermes' && sub === 'gateway' && GATEWAY_DENY.has(nonDash[k + 1] ?? '')) {
                        out.offer('deny', 'command', `openclaw gateway ${nonDash[k + 1]}`);
                    }
                    if (b !== 'hermes' && sub === 'doctor' && (rest.includes('--fix') || rest.includes('--repair'))) {
                        out.offer('deny', 'command', 'openclaw doctor --fix');
                    }
                }
            }
            if (NODE_PMS.has(b)) {
                const rest = words.slice(i + 1);
                if (rest.some((w) => NODE_PM_VERBS.has(w)) && rest.some((w) => NODE_PROTECTED.has(packageName(w)))) {
                    out.offer('deny', 'command', `${b} changes the OpenClaw or Guard package`);
                }
            }
            const isPip = b === 'pip' || b === 'pip3' || b === 'pipx' || (b === 'uv' && words[i + 1] === 'pip');
            if (isPip) {
                const rest = words.slice(i + 1);
                if (rest.some((w) => PY_VERBS.has(w)) && rest.some((w) => PY_PROTECTED.has(pyPackageName(w)))) {
                    out.offer('deny', 'command', `${b} changes the Hermes or Guard package`);
                }
            }
            if (b === 'pkill' || b === 'killall') {
                if (words.slice(i + 1).some((w) => /openclaw|hermes/i.test(w)))
                    out.offer('deny', 'command', `${b} stops the agent host`);
            }
            if (b === 'systemctl' || b === 'launchctl') {
                const rest = words.slice(i + 1);
                if (rest.some((w) => SERVICE_VERBS.has(w)) && rest.some((w) => /openclaw|hermes/i.test(w))) {
                    out.offer('deny', 'command', `${b} stops the agent host`);
                }
            }
            if (b === 'crontab') {
                const rest = words.slice(i + 1);
                let edits = false;
                for (let k = 0; k < rest.length; k++) {
                    const w = rest[k];
                    if (w === '-u') {
                        k++;
                        continue;
                    }
                    if (w === '-')
                        edits = true;
                    else if (w.startsWith('-')) {
                        if (/[er]/.test(w.slice(1)))
                            edits = true;
                    }
                    else
                        edits = true;
                }
                if (edits)
                    out.offer('approve', 'command', 'crontab');
            }
        }
        if (commandWord(words) === 'at')
            out.offer('approve', 'command', 'at');
    }
    if (ENVIRON_RE.test(text))
        out.offer('approve', 'command', "reads a process's environment");
    if (tainted) {
        if (PIPE_TO_SHELL_RE.test(text) || PROCESS_SUBST_SHELL_RE.test(text))
            out.offer('approve', 'command', 'pipes into a shell or interpreter');
        if (DECODE_RE.test(text) && RUNNER_RE.test(text))
            out.offer('approve', 'command', 'decodes and runs');
    }
}
/** §5.3: scan one shell command or piece of code. */
export function scanCommand(text, workdir, rules, shell, env, tainted, out = new Strictest()) {
    const expanded = expandShellHome(text, env.home);
    let realpathBudget = MAX_REALPATH_TOKENS;
    for (const token of expanded.split(SHELL_SPLIT)) {
        if (!token)
            continue;
        const pathLike = token.includes('/') || token.startsWith('~') || token.startsWith('.') || isSecretFileName(baseWord(token), rules.caseInsensitive);
        if (!pathLike)
            continue;
        const abs = resolvePath(token, workdir, env);
        const r = pathRuleFor(rules, env, abs, 'shell', realpathBudget-- > 0);
        if (r.cls)
            out.offer(r.rule, r.cls, `path class ${r.cls}`);
        if (out.denied)
            return out.result;
    }
    for (const { cls, re } of shell.substrings) {
        if (re.test(expanded)) {
            out.offer('deny', cls, `mentions a ${cls} path`);
            return out.result;
        }
    }
    commandPatterns(expanded, tainted, out);
    return out.result;
}
/** SPEC §5: every hard rule for one classified call. */
export function evaluateHardRules(classified, rules, shell, env, opts) {
    const out = new Strictest();
    const c = classified.classification;
    if (c.hardRule)
        out.offer(c.hardRule, 'tool', `tool rule for ${c.tool}`);
    if (out.denied)
        return out.result;
    const isShell = (classified.entry?.commandArgs?.length ?? 0) > 0;
    const column = isShell ? 'shell' : c.risk === 'read' ? 'read' : 'write';
    for (const p of c.paths) {
        const r = pathRuleFor(rules, env, p, column, true);
        if (r.cls)
            out.offer(r.rule, r.cls, `path class ${r.cls}`);
        if (out.denied)
            return out.result;
    }
    for (const text of classified.commands) {
        scanCommand(text, classified.workdir, rules, shell, env, opts.tainted, out);
        if (out.denied)
            return out.result;
    }
    return out.result;
}
