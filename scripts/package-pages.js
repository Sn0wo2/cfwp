const {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
} = require("node:fs");
const { dirname, isAbsolute, relative, resolve, sep } = require("node:path");

const root = resolve(__dirname, "..");
const buildDir = resolve(root, "build");
const worker = resolve(buildDir, "index.js");
const outputDir = resolve(root, "pages", "public");

if (!existsSync(worker)) throw new Error("Worker build output is missing: build/index.js");

const source = readFileSync(worker, "utf8");
const wasmImport = source.match(/\bfrom\s*["']([^"']+\.wasm)["']/)?.[1];
if (!wasmImport) throw new Error("Could not find the imported Wasm module in build/index.js");

const wasm = resolve(dirname(worker), wasmImport);
const wasmRelative = relative(buildDir, wasm);
if (
  isAbsolute(wasmRelative) ||
  wasmRelative === ".." ||
  wasmRelative.startsWith(`..${sep}`)
)
  throw new Error("Worker Wasm module must be inside the build directory");
if (!existsSync(wasm)) throw new Error(`Worker Wasm module is missing: ${wasmRelative}`);

rmSync(outputDir, { recursive: true, force: true });
mkdirSync(outputDir, { recursive: true });
copyFileSync(worker, resolve(outputDir, "_worker.js"));
const wasmOutput = resolve(outputDir, wasmRelative);
mkdirSync(dirname(wasmOutput), { recursive: true });
copyFileSync(wasm, wasmOutput);

console.log(`Packaged Pages Worker and ${wasmRelative} into pages/public`);
