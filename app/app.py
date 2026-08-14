from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/")
def home():
    return "Mini ASPM Lab"

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"Hello {name}"

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    result = subprocess.run(
        "ping -n 1 " + host,
        shell=True,
        capture_output=True,
        text=True
    )

    return result.stdout

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)