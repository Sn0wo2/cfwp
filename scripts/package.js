const { existsSync, readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");

const root = resolve(__dirname, "..");
for (const file of [
  "build/index.js",
  "build/package.json",
  "build/worker/index.wasm",
  "build/worker/shim.mjs",
]) {
  if (!existsSync(resolve(root, file)))
    throw new Error(`Missing Worker artifact: ${file}`);
}
let skip = false;
const config = readFileSync(resolve(root, "wrangler.example.toml"), "utf8")
  .split(/\r?\n/)
  .filter((line) => {
    if (line.trimStart().startsWith("["))
      skip = /^\[build(?:\]|\.)/.test(line.trim());
    return !skip;
  })
  .join("\n")
  .trimEnd();
writeFileSync(resolve(root, "build/wrangler.toml"), `${config}\n`);
