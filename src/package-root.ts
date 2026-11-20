import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

let cached: string | undefined;

/**
 * The directory of this package (it holds `openclaw.plugin.json`). The code
 * runs from `src/` in tests and from `dist/` when installed; both sit below it.
 */
export function packageRoot(): string {
  if (cached) return cached;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    if (existsSync(join(dir, 'openclaw.plugin.json')) && existsSync(join(dir, 'package.json'))) {
      cached = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('LumoAuth Guard: cannot find its package directory (openclaw.plugin.json is missing).');
}

/** Read a JSON file inside the package. */
export function readPackageJson<T>(relativePath: string): T {
  return JSON.parse(readFileSync(join(packageRoot(), relativePath), 'utf8')) as T;
}

/** This package's version, from package.json. */
export function packageVersion(): string {
  try {
    return readPackageJson<{ version?: string }>('package.json').version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
