const { execFile } = require("child_process");
const tokenDir = process.env.VIEWER_TOKEN_DIR;
execFile("xdg-open", [tokenDir]);
