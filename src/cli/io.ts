import { createInterface } from 'node:readline/promises';

/** Where CLI commands write and read. Tests pass their own. */
export interface CliIo {
  out(line?: string): void;
  err(line: string): void;
  /** Rewrite the current terminal line (spinner); no-op when not a TTY. */
  status(text: string): void;
  /** Clear a status line. */
  clearStatus(): void;
  isTTY: boolean;
  color: boolean;
  /** Ask a question (TTY only). */
  prompt?: ((question: string) => Promise<string>) | undefined;
  setExitCode(code: number): void;
}

export function processIo(): CliIo {
  const isTTY = Boolean(process.stdout.isTTY && process.stdin.isTTY);
  const color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
  let statusShown = false;
  return {
    out: (line = '') => {
      if (statusShown) {
        process.stdout.write('\r\x1b[2K');
        statusShown = false;
      }
      process.stdout.write(`${line}\n`);
    },
    err: (line) => process.stderr.write(`${line}\n`),
    status: (text) => {
      if (!process.stdout.isTTY) return;
      process.stdout.write(`\r\x1b[2K${text}`);
      statusShown = true;
    },
    clearStatus: () => {
      if (statusShown) process.stdout.write('\r\x1b[2K');
      statusShown = false;
    },
    isTTY,
    color,
    prompt: isTTY
      ? async (question) => {
          const rl = createInterface({ input: process.stdin, output: process.stdout });
          try {
            return (await rl.question(question)).trim();
          } finally {
            rl.close();
          }
        }
      : undefined,
    setExitCode: (code) => {
      process.exitCode = code;
    },
  };
}

export interface Style {
  bold(s: string): string;
  dim(s: string): string;
  green(s: string): string;
  yellow(s: string): string;
  red(s: string): string;
  cyan(s: string): string;
}

export function style(io: CliIo): Style {
  const wrap = (code: string) => (s: string) => (io.color ? `\x1b[${code}m${s}\x1b[0m` : s);
  return { bold: wrap('1'), dim: wrap('2'), green: wrap('32'), yellow: wrap('33'), red: wrap('31'), cyan: wrap('36') };
}

export const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export function levelMark(level: string, s: Style): string {
  switch (level) {
    case 'ok':
      return s.green('✓');
    case 'info':
      return s.cyan('i');
    case 'warn':
      return s.yellow('!');
    default:
      return s.red('✗');
  }
}
