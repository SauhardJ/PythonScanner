"""A deliberately vulnerable Flask app for testing our scanner."""
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)
app.secret_key = "password123"


@app.route("/")
def index():
    return "<h1>Welcome</h1>"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("test.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query).fetchall()
    conn.close()
    return str(result)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    return f"<h1>Results for: {term}</h1>"


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    template = f"<h1>Hello {name}</h1>"
    return render_template_string(template)


if __name__ == "__main__":
    app.run(debug=True)