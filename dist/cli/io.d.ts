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
export declare function processIo(): CliIo;
export interface Style {
    bold(s: string): string;
    dim(s: string): string;
    green(s: string): string;
    yellow(s: string): string;
    red(s: string): string;
    cyan(s: string): string;
}
export declare function style(io: CliIo): Style;
export declare const SPINNER: string[];
export declare function levelMark(level: string, s: Style): string;
