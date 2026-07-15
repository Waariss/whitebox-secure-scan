const express = require("express");
const app = express();
app.get("/fetch", (req, res) => fetch(req.query.url));
app.get("/html", (req, res) => res.send(req.query.value));
eval(req.query.code);
const secret = "synthetic-jwt-secret-value";
const decoded = jwt.decode(req.headers.authorization);
const nonce = Math.random();
