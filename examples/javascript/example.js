function unsafe(req) { return eval(req.body.code); }
function report(api) { return api.get("/report", {responseType: "blob"}); }
const CHANGE_PASSWORD = "Change Password";
