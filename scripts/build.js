const { existsSync } = require("node:fs");
const { resolve } = require("node:path");
const { runCommand } = require("./utils");

const root = resolve(__dirname, "..");
const mode = process.argv[2] || "release";
const features = [
  ...new Set(
    (process.env.CFWP_FEATURES ?? "proxy")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  ),
];
if (
  !["dev", "release"].includes(mode) ||
  !features.length ||
  features.some((value) => !["dns", "proxy"].includes(value))
) {
  console.error(
    "Usage: node scripts/build.js [dev|release]; CFWP_FEATURES must be dns, proxy, or dns,proxy",
  );
  process.exit(1);
}

function run(command, args) {
  const result = runCommand(command, args);
  if (result.error || result.status !== 0) process.exit(result.status ?? 1);
}

run("worker-build", [
  `--${mode}`,
  ".",
  "--no-panic-recovery",
  "--no-default-features",
  "--features",
  features.join(","),
  "-Z",
  "build-std=std,panic_abort",
]);
if (mode === "release") {
  const wasm = ["build/worker/index.wasm", "build/index_bg.wasm"].find((path) =>
    existsSync(resolve(root, path)),
  );
  if (!wasm) throw new Error("Worker build did not produce a Wasm module");
  run("wasm-opt", [wasm, "-Oz", "--strip-debug", "--strip-producers", "-o", wasm]);
}
