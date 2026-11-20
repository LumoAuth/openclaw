import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseConfig, type GuardConfig, type LoadedConfig } from './config.ts';
import { loadPrivateKey } from './lumoauth/crypto.ts';
import type { KeyObject } from 'node:crypto';

/** SPEC §3: `$LUMOAUTH_GUARD_HOME`, else `~/.lumoauth/guard/openclaw`. */
export function resolveGuardHome(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  const fromEnv = env.LUMOAUTH_GUARD_HOME?.trim();
  if (fromEnv) {
    const expanded = fromEnv === '~' ? home : fromEnv.startsWith('~/') ? join(home, fromEnv.slice(2)) : fromEnv;
    return resolve(expanded);
  }
  return join(home, '.lumoauth', 'guard', 'openclaw');
}

export const IS_POSIX = process.platform !== 'win32';

/** The files of the Guard home. */
export class GuardHome {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
  }
  get configPath(): string {
    return join(this.dir, 'config.json');
  }
  get keyPath(): string {
    return join(this.dir, 'agent-key.pem');
  }
  get lockPath(): string {
    return join(this.dir, 'lock');
  }
  /** Written by the gateway process so that `status` (another process) can show recent decisions and the receipt queue. */
  get statusPath(): string {
    return join(this.dir, 'status.json');
  }

  /** Create the directory with mode 0700 (and tighten it when it exists). */
  ensure(): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (IS_POSIX) chmodSync(this.dir, 0o700);
  }

  /** Write a file with mode 0600, atomically (temp file + rename). */
  writeSecure(path: string, content: string): void {
    this.ensure();
    const tmp = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    try {
      writeFileSync(tmp, content, { mode: 0o600, flag: 'wx' });
      if (IS_POSIX) chmodSync(tmp, 0o600);
      renameSync(tmp, path);
    } finally {
      rmSync(tmp, { force: true });
    }
  }

  readConfig(): LoadedConfig & { exists: boolean } {
    if (!existsSync(this.configPath)) return { config: null, issues: [], exists: false };
    try {
      return { ...parseConfig(JSON.parse(readFileSync(this.configPath, 'utf8'))), exists: true };
    } catch (err) {
      return { config: null, issues: [], exists: true, error: `config.json cannot be read: ${(err as Error).message}` };
    }
  }

  writeConfig(config: GuardConfig): void {
    this.writeSecure(this.configPath, `${JSON.stringify(config, null, 2)}\n`);
  }

  hasKey(): boolean {
    return existsSync(this.keyPath);
  }

  readKey(): KeyObject {
    return loadPrivateKey(readFileSync(this.keyPath, 'utf8'));
  }

  writeKey(pem: string): void {
    this.writeSecure(this.keyPath, pem);
  }

  readLock(): { at: string; reason: string } | null {
    let text: string;
    try {
      text = readFileSync(this.lockPath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      // Present but unreadable: treat as locked.
      return { at: '', reason: 'lock file present' };
    }
    const [at = '', ...rest] = text.trim().split(/\s+/);
    return { at, reason: rest.join(' ') };
  }

  isLocked(): boolean {
    return existsSync(this.lockPath);
  }

  lock(reason: string, now = new Date()): void {
    this.writeSecure(this.lockPath, `${now.toISOString()} ${reason.replace(/[\r\n]+/g, ' ').trim()}\n`);
  }

  unlock(): boolean {
    if (!existsSync(this.lockPath)) return false;
    rmSync(this.lockPath, { force: true });
    return true;
  }

  /** The last report written by a running Guard (status.json), or null. */
  readStatusReport(): Record<string, any> | null {
    try {
      return JSON.parse(readFileSync(this.statusPath, 'utf8'));
    } catch {
      return null;
    }
  }

  /** Mode bits of a file (POSIX), or undefined. */
  mode(path: string): number | undefined {
    try {
      return statSync(path).mode & 0o777;
    } catch {
      return undefined;
    }
  }
}
