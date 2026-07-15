import subprocess


def lookup(request, db):
    return db.execute("select * from users where id=" + request.args["id"])


def run(request):
    return subprocess.run(request.form["command"], shell=True)
