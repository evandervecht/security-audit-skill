# SA-PY-19: SSTI via render_template_string on user input (VULNERABLE)
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    page = "<h1>Hello " + name + "</h1>"
    return render_template_string(page)
