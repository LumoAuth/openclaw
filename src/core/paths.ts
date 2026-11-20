import { posix, win32 } from 'node:path';

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
  aliases?: { stateDir?: string | undefined; lumoauthRoot?: string | undefined } | undefined;
}

export type PathClass = 'guard' | 'hostConfig' | 'hostSkills' | 'hostState' | 'secrets' | 'secretFile' | 'persistence';

export function isCaseInsensitive(platform: string): boolean {
  return platform === 'darwin' || platform === 'win32';
}

function pathApi(platform: string) {
  return platform === 'win32' ? win32 : posix;
}

/** Use '/' everywhere so one set of patterns works on every platform. */
export function toSlashes(p: string): string {
  return p.replace(/\\/g, '/');
}

/** Expand `~`, `~/…`, `$HOME` and `${HOME}`. */
export function expandHome(p: string, home: string): string {
  let out = p.replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home);
  if (out === '~') out = home;
  else if (out.startsWith('~/') || out.startsWith('~\\')) out = home + out.slice(1);
  return out;
}

/** Absolute, lexically normalised form of `p` (relative paths resolve against `base`). */
export function resolvePath(p: string, base: string, env: Pick<GuardEnv, 'home' | 'platform'>): string {
  const api = pathApi(env.platform);
  const expanded = expandHome(p.trim(), env.home);
  const abs = api.isAbsolute(expanded) ? api.normalize(expanded) : api.resolve(base, expanded);
  let out = toSlashes(abs);
  if (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  return out;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Compile a path pattern: `<dir>/**` matches the directory and everything
 * below it; `*` matches within one segment (so `openclaw.json*` also covers
 * `openclaw.json.bak`).
 */
export function compilePattern(pattern: string, caseInsensitive: boolean): RegExp {
  let p = toSlashes(pattern);
  let tail = '';
  if (p.endsWith('/**')) {
    p = p.slice(0, -3);
    tail = '(?:/.*)?';
  }
  const body = p
    .split('*')
    .map(escapeRegex)
    .join('[^/]*');
  return new RegExp(`^${body}${tail}$`, caseInsensitive ? 'i' : '');
}

/** The literal part of a pattern before its first wildcard (for substring scans). */
export function patternRoot(pattern: string): { root: string; isDir: boolean; prefixFile: boolean } {
  const p = toSlashes(pattern);
  if (p.endsWith('/**')) {
    const dir = p.slice(0, -3);
    const star = dir.indexOf('*');
    if (star === -1) return { root: dir, isDir: true, prefixFile: false };
    // `<state>/agents/*/agent/**` → `<state>/agents/` (a directory root).
    return { root: dir.slice(0, dir.lastIndexOf('/', star)), isDir: true, prefixFile: false };
  }
  if (p.endsWith('*') && !p.slice(0, -1).includes('*')) return { root: p.slice(0, -1), isDir: false, prefixFile: true };
  const star = p.indexOf('*');
  if (star === -1) return { root: p, isDir: false, prefixFile: false };
  return { root: p.slice(0, p.lastIndexOf('/', star)), isDir: true, prefixFile: false };
}

export interface PathRules {
  caseInsensitive: boolean;
  classes: { cls: Exclude<PathClass, 'secretFile'>; patterns: string[]; regexes: RegExp[] }[];
  hostStateExceptions: RegExp[];
  /** Patterns of the classes that a shell substring scan looks for (guard, hostConfig, secrets). */
  substringPatterns: { cls: PathClass; pattern: string }[];
}

const SECRET_HOME_PATTERNS = [
  '.ssh/**',
  '.gnupg/**',
  '.aws/**',
  '.azure/**',
  '.config/gcloud/**',
  '.kube/**',
  '.docker/config.json',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.git-credentials',
  '.config/gh/hosts.yml',
  '.password-store/**',
  'Library/Keychains/**',
  '.config/google-chrome/**',
  '.config/chromium/**',
  '.mozilla/**',
  'Library/Application Support/Google/Chrome/**',
  'Library/Application Support/Firefox/**',
];

const PERSISTENCE_HOME_PATTERNS = [
  '.bashrc',
  '.bash_profile',
  '.profile',
  '.zshrc',
  '.zprofile',
  '.zshenv',
  '.config/fish/config.fish',
  '.config/autostart/**',
  '.config/systemd/user/**',
  'Library/LaunchAgents/**',
];

function asDirPattern(p: string): string {
  return p.endsWith('/**') ? p : `${p}/**`;
}

/** Build the §5.1 path rules for OpenClaw from the environment. */
export function buildPathRules(env: GuardEnv): PathRules {
  const ci = isCaseInsensitive(String(env.platform));
  const home = toSlashes(env.home).replace(/\/+$/, '');
  const state = toSlashes(env.stateDir).replace(/\/+$/, '');
  const abs = (p: string) => resolvePath(p, home, env);

  const states = [state];
  const realState = env.aliases?.stateDir ? toSlashes(env.aliases.stateDir).replace(/\/+$/, '') : '';
  if (realState && realState !== state) states.push(realState);

  const guard = [`${home}/.lumoauth/**`];
  const realLumo = env.aliases?.lumoauthRoot ? toSlashes(env.aliases.lumoauthRoot).replace(/\/+$/, '') : '';
  if (realLumo && realLumo !== `${home}/.lumoauth`) guard.push(`${realLumo}/**`);
  const guardHome = abs(env.guardHome);
  if (!guardHome.startsWith(`${home}/.lumoauth/`) && guardHome !== `${home}/.lumoauth`) guard.push(`${guardHome}/**`);

  const hostConfig = states.flatMap((s) => [
    `${s}/openclaw.json*`,
    `${s}/.env`,
    `${s}/credentials/**`,
    `${s}/agents/*/agent/**`,
    `${s}/npm/**`,
    `${s}/extensions/**`,
    `${s}/state/**`,
  ]);
  if (env.configPathFromEnv) hostConfig.push(`${abs(env.configPathFromEnv)}*`);
  if (env.pluginDir) hostConfig.push(`${abs(env.pluginDir)}/**`);

  // Skills: the model reads them (instructions); only the owner writes them.
  const hostSkills = states.flatMap((s) => [`${s}/skills/**`, `${s}/plugin-skills/**`]);

  const hostState = states.map((s) => `${s}/**`);
  const exceptions = [
    ...states.map((s) => `${s}/workspace*/**`),
    ...env.workspaces.map((w) => asDirPattern(abs(w))),
    ...env.allowPaths.filter((p) => p.trim() !== '').map((p) => asDirPattern(abs(p))),
  ];

  const secrets = [
    ...SECRET_HOME_PATTERNS.map((p) => `${home}/${p}`),
    ...env.extraProtectedPaths.filter((p) => p.trim() !== '').map((p) => asDirPattern(abs(p))),
  ];
  const persistence = PERSISTENCE_HOME_PATTERNS.map((p) => `${home}/${p}`);

  const mk = (cls: Exclude<PathClass, 'secretFile'>, patterns: string[]) => ({
    cls,
    patterns,
    regexes: patterns.map((p) => compilePattern(p, ci)),
  });
  return {
    caseInsensitive: ci,
    classes: [
      mk('guard', guard),
      mk('hostConfig', hostConfig),
      mk('hostSkills', hostSkills),
      mk('hostState', hostState),
      mk('secrets', secrets),
      mk('persistence', persistence),
    ],
    hostStateExceptions: exceptions.map((p) => compilePattern(p, ci)),
    substringPatterns: [
      ...guard.map((pattern) => ({ cls: 'guard' as const, pattern })),
      ...hostConfig.map((pattern) => ({ cls: 'hostConfig' as const, pattern })),
      ...secrets.map((pattern) => ({ cls: 'secrets' as const, pattern })),
    ],
  };
}

const SECRET_FILE_ALLOWED_ENV = new Set(['.env.example', '.env.sample', '.env.template', '.env.dist']);

/** SPEC §5.1 `secretFile`: `.env`, `.env.*` (not the example files), `*.pem`, `*.key`, SSH private key names. */
export function isSecretFileName(name: string, caseInsensitive: boolean): boolean {
  const n = caseInsensitive ? name.toLowerCase() : name;
  if (n === '.env') return true;
  if (n.startsWith('.env.')) return !SECRET_FILE_ALLOWED_ENV.has(n);
  if (n.endsWith('.pem') || n.endsWith('.key')) return n.length > 4;
  return n.startsWith('id_rsa') || n.startsWith('id_ed25519') || n.startsWith('id_ecdsa');
}

function baseName(p: string): string {
  const s = toSlashes(p).replace(/\/+$/, '');
  return s.slice(s.lastIndexOf('/') + 1);
}

/** The first §5.1 class that matches an absolute path, in the table's order. */
export function classifyPath(rules: PathRules, absPath: string): PathClass | null {
  const p = toSlashes(absPath);
  for (const c of rules.classes) {
    if (c.cls === 'persistence') {
      // secretFile comes before persistence in the table.
      if (isSecretFileName(baseName(p), rules.caseInsensitive)) return 'secretFile';
    }
    if (!c.regexes.some((r) => r.test(p))) continue;
    if (c.cls === 'hostState' && rules.hostStateExceptions.some((r) => r.test(p))) continue;
    return c.cls;
  }
  return null;
}
