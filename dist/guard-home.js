import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseConfig } from "./config.js";
import { loadPrivateKey } from "./lumoauth/crypto.js";
/** SPEC §3: `$LUMOAUTH_GUARD_HOME`, else `~/.lumoauth/guard/openclaw`. */
export function resolveGuardHome(env = process.env, home = homedir()) {
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
    dir;
    constructor(dir) {
        this.dir = dir;
    }
    get configPath() {
        return join(this.dir, 'config.json');
    }
    get keyPath() {
        return join(this.dir, 'agent-key.pem');
    }
    get lockPath() {
        return join(this.dir, 'lock');
    }
    /** Written by the gateway process so that `status` (another process) can show recent decisions and the receipt queue. */
    get statusPath() {
        return join(this.dir, 'status.json');
    }
    /** Create the directory with mode 0700 (and tighten it when it exists). */
    ensure() {
        mkdirSync(this.dir, { recursive: true, mode: 0o700 });
        if (IS_POSIX)
            chmodSync(this.dir, 0o700);
    }
    /** Write a file with mode 0600, atomically (temp file + rename). */
    writeSecure(path, content) {
        this.ensure();
        const tmp = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
        try {
            writeFileSync(tmp, content, { mode: 0o600, flag: 'wx' });
            if (IS_POSIX)
                chmodSync(tmp, 0o600);
            renameSync(tmp, path);
        }
        finally {
            rmSync(tmp, { force: true });
        }
    }
    readConfig() {
        if (!existsSync(this.configPath))
            return { config: null, issues: [], exists: false };
        try {
            return { ...parseConfig(JSON.parse(readFileSync(this.configPath, 'utf8'))), exists: true };
        }
        catch (err) {
            return { config: null, issues: [], exists: true, error: `config.json cannot be read: ${err.message}` };
        }
    }
    writeConfig(config) {
        this.writeSecure(this.configPath, `${JSON.stringify(config, null, 2)}\n`);
    }
    hasKey() {
        return existsSync(this.keyPath);
    }
    readKey() {
        return loadPrivateKey(readFileSync(this.keyPath, 'utf8'));
    }
    writeKey(pem) {
        this.writeSecure(this.keyPath, pem);
    }
    readLock() {
        let text;
        try {
            text = readFileSync(this.lockPath, 'utf8');
        }
        catch (err) {
            if (err.code === 'ENOENT')
                return null;
            // Present but unreadable: treat as locked.
            return { at: '', reason: 'lock file present' };
        }
        const [at = '', ...rest] = text.trim().split(/\s+/);
        return { at, reason: rest.join(' ') };
    }
    isLocked() {
        return existsSync(this.lockPath);
    }
    lock(reason, now = new Date()) {
        this.writeSecure(this.lockPath, `${now.toISOString()} ${reason.replace(/[\r\n]+/g, ' ').trim()}\n`);
    }
    unlock() {
        if (!existsSync(this.lockPath))
            return false;
        rmSync(this.lockPath, { force: true });
        return true;
    }
    /** The last report written by a running Guard (status.json), or null. */
    readStatusReport() {
        try {
            return JSON.parse(readFileSync(this.statusPath, 'utf8'));
        }
        catch {
            return null;
        }
    }
    /** Mode bits of a file (POSIX), or undefined. */
    mode(path) {
        try {
            return statSync(path).mode & 0o777;
        }
        catch {
            return undefined;
        }
    }
}
