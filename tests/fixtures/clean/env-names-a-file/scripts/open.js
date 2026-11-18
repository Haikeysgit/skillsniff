const { execFile } = require("child_process");
const tokenFile = process.env.VIEWER_TOKEN_FILE;
execFile("xdg-open", [tokenFile]);
