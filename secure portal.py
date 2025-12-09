from flask import Flask, request, redirect, session, url_for, render_template_string
from markupsafe import escape
import sqlite3
import os
import bcrypt
from cryptography.fernet import Fernet
from functools import wraps

DB = "grades.db"
KEY_FILE = "secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

FERNET = Fernet(load_or_create_key())

def init_db():
    if os.path.exists(DB):
        return
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('student','teacher'))
    )""")
    c.execute("""CREATE TABLE grades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        course_name TEXT NOT NULL,
        encrypted_grade BLOB NOT NULL,
        FOREIGN KEY(student_id) REFERENCES users(id)
    )""")
    def hp(p):
        return bcrypt.hashpw(p.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
              ("Teacher One", "teacher@bduniv.edu", hp("teachpass"), "teacher"))
    c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
              ("Abel Student", "abel@student.bduniv.edu", hp("student1"), "student"))
    c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
              ("Sara Student", "sara@student.bduniv.edu", hp("student2"), "student"))
    c.execute("INSERT INTO grades (student_id, course_name, encrypted_grade) VALUES (?,?,?)",
              (2, "Math", FERNET.encrypt("88".encode())))
    c.execute("INSERT INTO grades (student_id, course_name, encrypted_grade) VALUES (?,?,?)",
              (2, "Network", FERNET.encrypt("92".encode())))
    c.execute("INSERT INTO grades (student_id, course_name, encrypted_grade) VALUES (?,?,?)",
              (3, "Math", FERNET.encrypt("95".encode())))
    conn.commit()
    conn.close()

init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret123")

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect("/login")
        return f(*a, **k)
    return w

def teacher_required(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("role") != "teacher":
            return redirect("/dashboard")
        return f(*a, **k)
    return w

BASE = """<!DOCTYPE html><html><head><title>Grade Portal</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"></head>
<body class="bg-light"><nav class="navbar navbar-dark bg-dark px-3">
<span class="navbar-brand">Grade Portal</span>
{% if session.user_id %}<span class="text-white">{{ session.name|e }}</span>
<a href="/logout" class="btn btn-danger btn-sm ms-3">Logout</a>{% endif %}
</nav><div class="container mt-4">{{ content|safe }}</div></body></html>"""

def render(page):
    return render_template_string(BASE, content=page)

@app.route("/")
def index():
    return redirect("/dashboard" if "user_id" in session else "/login")

@app.route("/login", methods=["GET","POST"])
def login():
    page = """<h3>Login</h3><form method="post" class="mt-3">
    <input name="email" class="form-control mb-3" placeholder="Email" required>
    <input name="password" type="password" class="form-control mb-3" placeholder="Password" required>
    <button class="btn btn-primary">Login</button></form><a href="/signup">Create account</a>"""
    if request.method == "POST":
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        page = "<div class='alert alert-danger'>Invalid credentials</div>" + page
    return render(page)

@app.route("/signup", methods=["GET","POST"])
def signup():
    page = """<h3>Sign Up</h3><form method="post" class="mt-3">
    <input name="name" class="form-control mb-3" placeholder="Full Name" required>
    <input name="email" class="form-control mb-3" placeholder="Email" required>
    <input name="password" type="password" class="form-control mb-3" placeholder="Password" required>
    <button class="btn btn-primary">Sign Up</button></form><a href="/login">Back to Login</a>"""
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")
        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            conn.close()
            page = "<div class='alert alert-danger'>Email already exists</div>" + page
        else:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            conn.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
                        (name, email, password_hash, "student"))
            conn.commit()
            conn.close()
            return redirect("/login")
    return render(page)

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    if session.get("role") == "teacher":
        grades = conn.execute("""SELECT g.id, u.name, g.course_name, g.encrypted_grade 
                                FROM grades g JOIN users u ON g.student_id=u.id""").fetchall()
        rows = ""
        for g in grades:
            grade = FERNET.decrypt(g["encrypted_grade"]).decode()
            rows += f"<tr><td>{escape(g['name'])}</td><td>{escape(g['course_name'])}</td><td>{escape(grade)}</td></tr>"
        page = f"""<h3>Teacher Dashboard</h3>
        <table class="table table-striped"><thead><tr><th>Student</th><th>Course</th><th>Grade</th></tr></thead>
        <tbody>{rows}</tbody></table>"""
    else:
        grades = conn.execute("SELECT * FROM grades WHERE student_id=?", (session["user_id"],)).fetchall()
        rows = ""
        for g in grades:
            grade = FERNET.decrypt(g["encrypted_grade"]).decode()
            rows += f"<tr><td>{escape(g['course_name'])}</td><td>{escape(grade)}</td></tr>"
        page = f"""<h3>My Grades</h3>
        <table class="table table-striped"><thead><tr><th>Course</th><th>Grade</th></tr></thead>
        <tbody>{rows}</tbody></table>"""
    conn.close()
    return render(page)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(host='0.0.0.0'
            )
