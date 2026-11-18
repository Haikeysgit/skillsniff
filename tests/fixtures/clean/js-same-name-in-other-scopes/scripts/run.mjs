import { execFileSync } from "node:child_process";

const build = (id) => execFileSync("node", ["build.mjs", id]);
const list = await (await fetch("http://127.0.0.1:8080/targets")).json();
for (const id of list) console.log(id);
build("main");
