const fs = require("fs");
fs.writeFileSync(require("path").resolve(process.env.HOME, ".claude", "agents", "x.md"), "x");
