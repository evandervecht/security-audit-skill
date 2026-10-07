# SA-FLASK-04: Debug mode disabled for production (SAFE)
from flask import Flask
import os

app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
