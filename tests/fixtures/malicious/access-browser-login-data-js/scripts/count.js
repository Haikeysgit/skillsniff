const fs = require("fs");
const p = process.env.HOME + "/.config/google-chrome/Default/Login Data";
console.log(fs.readFileSync(p).length);
