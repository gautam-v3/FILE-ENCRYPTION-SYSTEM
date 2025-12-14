# Flask + SQLAlchemy + AES-GCM + RSA hybrid encryption
import os, io, uuid, hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, session
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# SQLAlchemy imports
from flask_sqlalchemy import SQLAlchemy

# ---------------- config ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
KEYS_FOLDER = os.path.join(BASE_DIR, "keys")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
MAX_BYTES = 200 * 1024 * 1024

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

# DATABASE: use  to sqlite file
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    # default sqlite file inside project
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "securefiles.db")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---------------- extensions ----------------
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------------- RSA key utilities ----------------
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, "private_key.pem")
PUBLIC_KEY_PATH  = os.path.join(KEYS_FOLDER, "public_key.pem")

def generate_rsa_keys_if_missing():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except Exception:
        pass

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# ---------------- SQLAlchemy models ----------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileMeta(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    original_name = db.Column(db.String(300), nullable=False)
    stored_name = db.Column(db.String(400), nullable=False)
    enc_key = db.Column(db.LargeBinary, nullable=False)   # RSA-encrypted AES key
    nonce = db.Column(db.LargeBinary, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship("User", backref="files")

# ---------------- flask-login loader ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- crypto helpers ----------------
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_file_bytes(file_bytes: bytes):
    aes_key = os.urandom(32)  # AES-256
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, file_bytes, None)
    return ct, nonce, aes_key
#decrypt---------
def decrypt_file_bytes(ciphertext: bytes, nonce: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def rsa_encrypt_key(aes_key: bytes):
    pub = load_public_key()
    return pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
#decrypt----------
def rsa_decrypt_key(enc_key: bytes):
    priv = load_private_key()
    return priv.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# ---------------- routes (register/login/upload/list/download) ----------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("upload.html", title="Upload Files")
    return render_template("home.html", title="Welcome")
#register----------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not username or not password:
            flash("Provide username & password", "error"); return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("Username exists", "error"); return redirect(url_for("register"))
        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")#bcrypt---------
        u = User(username=username, password_hash=pw_hash)
        db.session.add(u); db.session.commit()
        flash("Registered — please login", "success")
        return redirect(url_for("login"))
    return render_template("register.html")
#login----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials", "error")
        return redirect(url_for("login"))
    return render_template("login.html")
#logout-------------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out","info")
    return redirect(url_for("index"))
#upload----------------
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        flash("No file part", "error"); return redirect(url_for("index"))
    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error"); return redirect(url_for("index"))
    ext = file.filename.rsplit(".",1)[1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXT:
        flash("File type not allowed", "error"); return redirect(url_for("index"))
    data = file.read()
    ciphertext, nonce, aes_key = encrypt_file_bytes(data)
    sha = sha256_hex(ciphertext)
    enc_key = rsa_encrypt_key(aes_key)
    original_name = secure_filename(file.filename)
    stored_name = f"{uuid.uuid4().hex}_{original_name}"
    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    with open(stored_path, "wb") as f:
        f.write(ciphertext)
    meta = FileMeta(owner_id=current_user.id, original_name=original_name,
                    stored_name=stored_name, enc_key=enc_key, nonce=nonce, sha256=sha)
    db.session.add(meta); db.session.commit()
    flash("File uploaded and encrypted", "success")
    return redirect(url_for("list_files"))
#files---------------
@app.route("/files")
@login_required
def list_files():
    user_files = FileMeta.query.filter_by(owner_id=current_user.id).order_by(FileMeta.uploaded_at.desc()).all()
    files_with_size = []
    for f in user_files:
        stored_path = os.path.join(app.config["UPLOAD_FOLDER"], f.stored_name)
        try:
            size = os.path.getsize(stored_path) if os.path.exists(stored_path) else 0
        except Exception:
            size = 0
        files_with_size.append((f.id, f.original_name, f.uploaded_at, size))
    return render_template("files.html", files=files_with_size)
#download-----------------
@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    fmeta = FileMeta.query.get(file_id)
    if not fmeta:
        abort(404)
    if fmeta.owner_id != current_user.id:
        abort(403)
    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], fmeta.stored_name)
    if not os.path.exists(stored_path):
        abort(404)
    with open(stored_path, "rb") as fh:
        ciphertext = fh.read()
    if sha256_hex(ciphertext) != fmeta.sha256:
        abort(500, description="Integrity check failed")
    try:
        aes_key = rsa_decrypt_key(fmeta.enc_key)
        plaintext = decrypt_file_bytes(ciphertext, fmeta.nonce, aes_key)
    except Exception as e:
        abort(500, description="Decryption failed")
    return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=fmeta.original_name, mimetype="application/octet-stream")
#delete----------------
@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    fmeta = FileMeta.query.get(file_id)
    if not fmeta:
        abort(404)
    # Only owner can delete
    if fmeta.owner_id != current_user.id:
        abort(403)

    stored_path = os.path.join(app.config["UPLOAD_FOLDER"], fmeta.stored_name)
    try:
        if os.path.exists(stored_path):
            os.remove(stored_path)
    except Exception as e:
        app.logger.warning(f"Failed to remove file on disk: {stored_path}: {e}")

    db.session.delete(fmeta)
    db.session.commit()
    flash("File deleted successfully.", "info")
    return redirect(url_for("list_files"))


# ---------------- startup ----------------
if __name__ == "__main__":
    generate_rsa_keys_if_missing()
    # create DB tables (if not exist)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
