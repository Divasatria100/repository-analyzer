// Minimal ambient declarations for the node builtins used by node-only
// test files. Avoids adding @types/node for three imports.
declare module "node:fs" {
  export function readFileSync(path: string, encoding: string): string;
}
declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
}
declare module "node:url" {
  export function fileURLToPath(url: string | { toString(): string }): string;
}
