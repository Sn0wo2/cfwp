const { existsSync, readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");

const root = resolve(__dirname, "..");
for (const file of [
  "build/index.js",
  "build/package.json",
  "build/worker/shim.mjs",
]) {
  if (!existsSync(resolve(root, file)))
    throw new Error(`Missing Worker artifact: ${file}`);
}
if (
  !["build/worker/index.wasm", "build/index_bg.wasm"].some((file) =>
    existsSync(resolve(root, file)),
  )
)
  throw new Error("Missing Worker Wasm artifact");
let skip = false;
const config = readFileSync(resolve(root, "wrangler.example.toml"), "utf8")
  .split(/\r?\n/)
  .filter((line) => {
    if (line.trimStart().startsWith("["))
      skip = /^\[build(?:\]|\.)/.test(line.trim());
    return !skip;
  })
  .map((line) =>
    line === 'main = "build/index.js"' ? 'main = "index.js"' : line,
  )
  .join("\n")
  .trimEnd();
writeFileSync(resolve(root, "build/wrangler.toml"), `${config}\n`);
