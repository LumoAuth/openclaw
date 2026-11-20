import { createInterface } from 'node:readline/promises';
export function processIo() {
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
            if (!process.stdout.isTTY)
                return;
            process.stdout.write(`\r\x1b[2K${text}`);
            statusShown = true;
        },
        clearStatus: () => {
            if (statusShown)
                process.stdout.write('\r\x1b[2K');
            statusShown = false;
        },
        isTTY,
        color,
        prompt: isTTY
            ? async (question) => {
                const rl = createInterface({ input: process.stdin, output: process.stdout });
                try {
                    return (await rl.question(question)).trim();
                }
                finally {
                    rl.close();
                }
            }
            : undefined,
        setExitCode: (code) => {
            process.exitCode = code;
        },
    };
}
export function style(io) {
    const wrap = (code) => (s) => (io.color ? `\x1b[${code}m${s}\x1b[0m` : s);
    return { bold: wrap('1'), dim: wrap('2'), green: wrap('32'), yellow: wrap('33'), red: wrap('31'), cyan: wrap('36') };
}
export const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
export function levelMark(level, s) {
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
