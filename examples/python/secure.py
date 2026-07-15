def lookup(request, db):
    return db.execute("select * from users where id=?", (request.args["id"],))
