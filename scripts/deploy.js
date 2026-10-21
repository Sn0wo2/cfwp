const { createPrompt, runCommand } = require("./utils");

const target = process.argv[2] || "worker";
if (!new Set(["worker", "pages"]).has(target)) {
  console.error("Usage: node scripts/deploy.js [worker|pages]");
  process.exit(1);
}

function confirm(prompt, question, defaultValue) {
  return prompt
    .ask(`${question} ${defaultValue ? "[Y/n]" : "[y/N]"} `)
    .then((value) => {
      const answer = value.trim().toLowerCase();
      if (!answer) return defaultValue;
      return answer === "y" || answer === "yes";
    });
}

(async () => {
  let prompt;
  try {
    console.log("Deployment helper\n");
      console.log(`\n==> Check Wrangler auth (${target})`);
    console.log("$ wrangler whoami");
    const result = runCommand("wrangler", ["whoami"], { stdio: "pipe" });
    if (result.status !== 0) {
      console.log("Wrangler authentication check failed.");
      if (result.stderr?.trim()) console.log(result.stderr.trim());
      if (result.stdout?.trim()) console.log(result.stdout.trim());
      return 1;
    }
    console.log((result.stdout || "").trim());

    prompt = createPrompt();
    if (await confirm(prompt, "Open secret helper first?", false)) {
      prompt.close();
      const secretStatus =
        runCommand(process.execPath, ["scripts/secrets.js", target]).status ?? 1;
      if (secretStatus !== 0) return secretStatus;
      prompt = createPrompt();
    }

    if (!(await confirm(prompt, "Deploy with wrangler now?", true))) {
      console.log("Canceled.");
      return 0;
    }

    if (target === "pages") {
      for (const args of [
        ["scripts/build.js", "release"],
        ["scripts/package-pages.js"],
      ]) {
        const result = runCommand(process.execPath, args);
        if (result.status !== 0) return result.status ?? 1;
      }
      console.log("\n==> Wrangler Pages deploy");
      console.log("$ wrangler pages deploy --cwd pages");
      prompt.close();
      return (
        runCommand("wrangler", ["pages", "deploy", "--cwd", "pages"])
          .status ?? 1
      );
    }

    console.log("\n==> Wrangler deploy");
    console.log("$ wrangler deploy");
    prompt.close();
    return runCommand("wrangler", ["deploy"]).status ?? 1;
  } finally {
    if (prompt) prompt.close();
  }
})()
  .then((status) => {
    process.exitCode = status;
  })
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
