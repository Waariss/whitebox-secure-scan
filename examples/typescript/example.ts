export async function unsafe(req: any) { return fetch(req.query.url); }
export async function safe() { return fetch("https://example.com/health"); }
