#!/usr/bin/env node
// Launch Electron with a clean environment. VS Code (itself Electron) exports
// ELECTRON_RUN_AS_NODE=1 to its terminals, which makes Electron behave as plain Node and
// `require("electron")` return undefined. Cross-platform alternative to `env -u`.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const electronPath = require("electron"); // the electron package exports the binary path
const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;

const child = spawn(electronPath, [".", ...process.argv.slice(2)], { stdio: "inherit", env });
child.on("exit", (code, signal) => {
  process.exit(code ?? (signal ? 1 : 0));
});
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    child.kill(sig);
  });
}
