const { createPrompt, runCommand } = require("./utils");

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
    console.log("\n==> Check Wrangler auth");
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
        runCommand(process.execPath, ["scripts/secrets.js"]).status ?? 1;
      if (secretStatus !== 0) return secretStatus;
      prompt = createPrompt();
    }

    if (!(await confirm(prompt, "Deploy with wrangler now?", true))) {
      console.log("Canceled.");
      return 0;
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
