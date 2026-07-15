import pickle
import subprocess
import yaml
import requests


def transfer(request):
    amount = request.args["amount"]
    return db.execute("SELECT * FROM accounts WHERE id = " + request.args["id"])


def run(request):
    subprocess.run(request.args["cmd"], shell=True)
    return requests.get(request.args["url"], verify=False)


TOKEN = "synthetic-token-value-12345"
data = pickle.loads(request.body)
config = yaml.load(request.body)
token = jwt.decode(request.headers["Authorization"])
nonce = random.random()
