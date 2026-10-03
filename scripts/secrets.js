const { existsSync, readFileSync, writeFileSync } = require("node:fs");
const { resolve } = require("node:path");
const { parseEnv } = require("node:util");
const { createPrompt, runCommand } = require("./utils");

const KNOWN_SECRETS = ["UUID", "PROXYIP", "PROXY", "DNS"];
const MASKED_KEYS = new Set(["UUID", "PROXYIP", "PROXY"]);
const devVars = resolve(__dirname, "..", ".dev.vars");

function readLocal() {
  return new Map(
    Object.entries(
      existsSync(devVars) ? parseEnv(readFileSync(devVars, "utf8")) : {},
    ),
  );
}

function putRemote(key, value) {
  return (
    runCommand("wrangler", ["secret", "put", key], {
      input: `${value}\n`,
      stdio: ["pipe", "inherit", "inherit"],
    }).status === 0
  );
}

(async () => {
  const prompt = createPrompt();
  try {
    while (true) {
      let remote = null;
      for (const args of [["--format", "json"], ["--json"], []]) {
        const result = runCommand("wrangler", ["secret", "list", ...args], {
          stdio: "pipe",
        });
        if (result.status !== 0) continue;
        const text = (result.stdout || "").trim();
        try {
          const data = JSON.parse(text);
          if (
            !Array.isArray(data) ||
            data.some(
              (item) =>
                typeof (typeof item === "string" ? item : item?.name) !==
                "string",
            )
          )
            continue;
          remote = new Set(
            data.map((item) => (typeof item === "string" ? item : item.name)),
          );
          break;
        } catch {
          const names = text
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter((line) => /^[A-Z_][A-Z0-9_]*$/.test(line));
          if (names.length) {
            remote = new Set(names);
            break;
          }
        }
      }
      if (remote === null)
        console.warn("Could not list remote secrets; remote state is unknown.");
      const local = readLocal();
      console.log("\nCurrent secret state\n");
      console.log(
        `${"Name".padEnd(15)} ${"Remote".padEnd(10)} ${"Local".padEnd(30)}`,
      );
      console.log(`${"-".repeat(15)} ${"-".repeat(10)} ${"-".repeat(30)}`);
      for (const name of KNOWN_SECRETS) {
        let value = local.get(name) ?? "missing";
        if (local.has(name) && MASKED_KEYS.has(name)) {
          const chars = [...value];
          value =
            chars.length <= 6
              ? "*".repeat(chars.length)
              : `${chars.slice(0, 3).join("")}...${chars.slice(-3).join("")}`;
        }
        console.log(
          `${name.padEnd(15)} ${(remote === null ? "unknown" : remote.has(name) ? "present" : "missing").padEnd(10)} ${value.padEnd(30)}`,
        );
      }
      const choice = (
        await prompt.ask(
          "\nChoose action: [1] set remote [2] set local [3] push local -> remote [4] refresh [0] quit\n> ",
        )
      ).trim();
      if (choice === "0") return;
      if (choice === "4") continue;
      if (choice === "1" || choice === "2") {
        KNOWN_SECRETS.forEach((name, index) =>
          console.log(`[${index + 1}] ${name}`),
        );
        console.log("[9] custom");
        const raw = (await prompt.ask("Choose secret key:\n> "))
          .trim()
          .toLowerCase();
        let key;
        if (raw === "9" || raw === "custom") {
          key = (await prompt.ask("Custom key:\n> ")).trim();
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
            console.log(
              "Invalid secret key. Use letters, digits, and underscores; do not start with a digit.",
            );
            continue;
          }
        } else if (/^[+-]?\d+$/.test(raw)) key = KNOWN_SECRETS[Number(raw) - 1];
        if (!key) continue;
        const value = (
          await prompt.ask(
            `Enter value for ${key}:\n> `,
            MASKED_KEYS.has(key) || !KNOWN_SECRETS.includes(key),
          )
        ).trim();
        if (!value) continue;
        if (choice === "1") {
          if (putRemote(key, value))
            console.log(`Remote secret updated: ${key}`);
        } else {
          const values = readLocal();
          values.set(key, value);
          writeFileSync(
            devVars,
            [...values.keys()]
              .sort()
              .map((name) => {
                const value = values.get(name);
                if (
                  !/[\r\n#]/.test(value) &&
                  value.trim() === value &&
                  !/^["'`]/.test(value)
                )
                  return `${name}=${value}\n`;
                for (const quote of ["'", '"', "`"])
                  if (!value.includes(quote)) {
                    const entry = `${name}=${quote}${value}${quote}\n`;
                    if (parseEnv(entry)[name] === value) return entry;
                  }
                throw new Error(`Cannot safely quote local secret: ${name}`);
              })
              .join(""),
            "utf8",
          );
          console.log(`Local .dev.vars updated: ${key}`);
        }
      } else if (choice === "3") {
        if (!local.size) {
          console.log("No local values found in .dev.vars");
          continue;
        }
        const available = KNOWN_SECRETS.filter((name) => local.has(name));
        available.forEach((name, index) =>
          console.log(`[${index + 1}] ${name}`),
        );
        const raw = (
          await prompt.ask(
            "Select entries to push (comma separated, empty cancels):\n> ",
          )
        ).trim();
        if (!raw) continue;
        const selections = raw
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        if (selections.some((item) => !/^[+-]?\d+$/.test(item))) {
          console.log("Invalid selection.");
          continue;
        }
        for (const [index, name] of available.entries()) {
          if (
            selections.some((item) => Number(item) === index + 1) &&
            putRemote(name, local.get(name))
          )
            console.log(`Pushed remote secret: ${name}`);
        }
      } else console.log("Unknown choice.");
    }
  } finally {
    prompt.close();
  }
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
