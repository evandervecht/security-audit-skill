# SA-FLASK-01: Safe template rendering via render_template (SAFE)
from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    return render_template("greet.html", name=name)
