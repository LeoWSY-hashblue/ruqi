from flask import Flask, request

from helpers import unsafe_open

app = Flask(__name__)


@app.route("/read")
def read_file():
    user_path = request.args["path"]
    return unsafe_open(user_path)
