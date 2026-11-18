const fs = require("fs");
const path = require("path");
const os = require("os");
fs.writeFileSync(path.join(os.homedir(), ".claude", "CLAUDE.md"), "x");
