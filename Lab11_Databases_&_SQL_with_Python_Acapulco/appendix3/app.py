import os
import sqlite3
import uuid

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config["SECRET_KEY"] = "profile_management_secret_key"
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = "profiles.db"

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png"}


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        image_filename TEXT
    )
    """)

    user = conn.execute(
        "SELECT id FROM users WHERE username = ?",
        ("student",)
    ).fetchone()

    if not user:
        conn.execute("""
        INSERT INTO users
        (username, password_hash, display_name, image_filename)
        VALUES (?, ?, ?, ?)
        """, (
            "student",
            generate_password_hash("password123"),
            "Student User",
            None
        ))

    conn.commit()
    conn.close()


class User(UserMixin):
    def __init__(self, user):
        self.id = user["id"]
        self.username = user["username"]
        self.display_name = user["display_name"]
        self.image_filename = user["image_filename"]


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    if user:
        return User(user)

    return None


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/", methods=["GET"])
def home():
    if current_user.is_authenticated:
        return redirect(url_for("profile"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            login_user(User(user))
            return redirect(url_for("profile"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        display_name = request.form["display_name"].strip()

        if not display_name:
            flash("Display name cannot be empty.")
            return redirect(url_for("profile"))

        image = request.files.get("image")
        image_filename = current_user.image_filename

        if image and image.filename:
            if not allowed_file(image.filename):
                flash("Only JPG, JPEG, and PNG images are allowed.")
                return redirect(url_for("profile"))

            if image.mimetype not in ALLOWED_MIME_TYPES:
                flash("Invalid image MIME type.")
                return redirect(url_for("profile"))

            original_name = secure_filename(image.filename)

            extension = original_name.rsplit(".", 1)[1].lower()

            image_filename = uuid.uuid4().hex + "." + extension

            image_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                image_filename
            )

            image.save(image_path)

        conn = get_db()

        conn.execute("""
        UPDATE users
        SET display_name = ?, image_filename = ?
        WHERE id = ?
        """, (
            display_name,
            image_filename,
            current_user.id
        ))

        conn.commit()
        conn.close()

        flash("Profile successfully updated!")

        return redirect(url_for("profile"))

    return render_template("profile.html", user=current_user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)