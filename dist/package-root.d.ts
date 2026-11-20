/**
 * The directory of this package (it holds `openclaw.plugin.json`). The code
 * runs from `src/` in tests and from `dist/` when installed; both sit below it.
 */
export declare function packageRoot(): string;
/** Read a JSON file inside the package. */
export declare function readPackageJson<T>(relativePath: string): T;
/** This package's version, from package.json. */
export declare function packageVersion(): string;
