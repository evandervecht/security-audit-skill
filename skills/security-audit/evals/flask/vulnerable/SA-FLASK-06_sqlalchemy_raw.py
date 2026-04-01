# SA-FLASK-06: SQLAlchemy raw query with f-string (VULNERABLE)
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


@app.route("/users")
def search_users():
    name = request.args.get("name")
    result = db.session.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return jsonify([dict(r) for r in result])
