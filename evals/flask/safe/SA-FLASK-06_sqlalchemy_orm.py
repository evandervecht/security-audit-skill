# SA-FLASK-06: Safe SQLAlchemy ORM query (SAFE)
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


@app.route("/users")
def search_users():
    name = request.args.get("name")
    users = User.query.filter_by(name=name).all()
    return jsonify([u.to_dict() for u in users])
