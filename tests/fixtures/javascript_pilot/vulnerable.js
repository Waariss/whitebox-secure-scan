const { exec } = require("child_process");
const fs = require("fs");
const multer = require("multer");
const sequelize = require("sequelize");

app.post("/upload", multer().single("file"), (req, res) => {
  fs.writeFile(req.file.originalname, req.file.buffer, () => res.sendStatus(201));
});
exec(req.body.command);
eval(req.body.code);
sequelize.query("SELECT * FROM customers WHERE id = " + req.query.id);
fetch(req.query.url);
document.body.innerHTML = req.body.html;
const JWT_SECRET = "actual-long-jwt-secret-value";
