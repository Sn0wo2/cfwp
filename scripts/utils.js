const { spawnSync } = require("node:child_process");
const { resolve } = require("node:path");
const { createInterface } = require("node:readline");
const { Writable } = require("node:stream");

function runCommand(command, args, options = {}) {
  if (command === "wrangler" && process.platform === "win32") {
    if (args.some((arg) => !/^[A-Za-z0-9_./:-]+$/.test(arg)))
      throw new Error("Invalid Wrangler argument.");
    args = ["/d", "/s", "/c", `wrangler ${args.join(" ")}`];
    command = process.env.ComSpec || "cmd.exe";
  }
  const result = spawnSync(command, args, {
    cwd: resolve(__dirname, ".."),
    stdio: "inherit",
    encoding: "utf8",
    ...options,
  });
  if (result.error) console.error(result.error.message);
  return result;
}

function createPrompt() {
  let muted = false;
  let interrupted = false;
  const input = createInterface({
    input: process.stdin,
    output: new Writable({
      write(chunk, encoding, callback) {
        if (!muted) process.stdout.write(chunk, encoding);
        callback();
      },
    }),
    terminal: Boolean(process.stdin.isTTY && process.stdout.isTTY),
  });
  const lines = input[Symbol.asyncIterator]();
  input.on("SIGINT", () => {
    interrupted = true;
    input.close();
  });
  return {
    async ask(text, masked = false) {
      muted = masked;
      process.stdout.write(text);
      try {
        const { value, done } = await lines.next();
        if (done) throw new Error(interrupted ? "Canceled." : "Input closed.");
        return value;
      } finally {
        muted = false;
        if (masked && input.terminal) process.stdout.write("\n");
      }
    },
    close() {
      input.close();
    },
  };
}

module.exports = { createPrompt, runCommand };
