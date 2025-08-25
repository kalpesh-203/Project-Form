import logging
import os
import sqlite3
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timedelta

from flask import Flask, g, jsonify, request, make_response

# Context variable to store request id per request/thread
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


def get_db_connection() -> sqlite3.Connection:
	db_path = os.getenv("DATABASE_URL", "/workspace/app.db")
	conn = sqlite3.connect(db_path, check_same_thread=False)
	conn.row_factory = sqlite3.Row
	return conn


def init_db_schema() -> None:
	conn = get_db_connection()
	try:
		with conn:
			conn.execute(
				"""
				CREATE TABLE IF NOT EXISTS users (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					fullname TEXT NOT NULL,
					email TEXT NOT NULL UNIQUE,
					username TEXT NOT NULL UNIQUE,
					password_hash TEXT NOT NULL,
					created_at TEXT NOT NULL
				);
				"""
			)
			conn.execute(
				"""
				CREATE TABLE IF NOT EXISTS surveys (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					user_id INTEGER NOT NULL,
					student_name TEXT NOT NULL,
					student_id TEXT NOT NULL,
					email TEXT NOT NULL,
					course TEXT NOT NULL,
					year INTEGER NOT NULL,
					feedback TEXT NOT NULL,
					created_at TEXT NOT NULL,
					FOREIGN KEY(user_id) REFERENCES users(id)
				);
				"""
			)
	finally:
		conn.close()


class JsonFormatter(logging.Formatter):
	def format(self, record: logging.LogRecord) -> str:
		payload = {
			"ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
			"level": record.levelname,
			"msg": record.getMessage(),
			"logger": record.name,
			"thread": threading.current_thread().name,
			"rid": request_id_ctx.get(),
		}
		if record.exc_info:
			payload["exc"] = self.formatException(record.exc_info)
		return json_dumps(payload)


def json_dumps(obj) -> str:
	# Manual lightweight JSON to avoid extra deps
	import json
	return json.dumps(obj, separators=(",", ":"))


def configure_logging() -> None:
	root = logging.getLogger()
	root.setLevel(logging.INFO)
	handler = logging.StreamHandler()
	handler.setFormatter(JsonFormatter())
	root.handlers = [handler]


app = Flask(__name__)


@app.before_request
def inject_request_id() -> None:
	incoming_rid = request.headers.get("X-Request-ID")
	rid = incoming_rid or uuid.uuid4().hex
	request_id_ctx.set(rid)
	# Expose on flask.g for convenience
	g.request_id = rid


@app.after_request
def set_response_headers(response):
	rid = request_id_ctx.get()
	response.headers["X-Request-ID"] = rid
	# primitive CORS for static file usage
	response.headers.setdefault("Access-Control-Allow-Origin", "*")
	response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, X-Request-ID")
	response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	return response


@app.route("/healthz", methods=["GET"])  # simple health endpoint
def healthz():
	return jsonify({"status": "ok", "time": int(time.time()), "rid": request_id_ctx.get()})


# --- auth helpers ---

def hash_password(plain: str) -> str:
	import hashlib
	# saltless for demo; replace with werkzeug.security for production
	return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
	return hash_password(plain) == hashed


def get_user_by_username(conn: sqlite3.Connection, username: str):
	cur = conn.execute("SELECT * FROM users WHERE username=?", (username,))
	return cur.fetchone()


# --- endpoints ---

@app.route("/api/signup", methods=["POST"])  # JSON or form-encoded
def api_signup():
	data = request.get_json(silent=True) or request.form
	fullname = (data.get("fullname") or "").strip()
	email = (data.get("email") or "").strip().lower()
	username = (data.get("username") or "").strip().lower()
	password = data.get("password") or ""
	if not (fullname and email and username and password):
		return jsonify({"error": "missing_fields"}), 400
	conn = get_db_connection()
	try:
		with conn:
			if get_user_by_username(conn, username):
				return jsonify({"error": "username_taken"}), 409
			conn.execute(
				"INSERT INTO users(fullname, email, username, password_hash, created_at) VALUES(?,?,?,?,?)",
				(fullname, email, username, hash_password(password), datetime.utcnow().isoformat()),
			)
			user_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
			resp = make_response(jsonify({"ok": True, "user_id": user_id}))
			# Set session cookie
			session_token = uuid.uuid4().hex
			# For demo: store session in-memory map (process-local)
			_sessions[session_token] = {"user_id": user_id, "username": username, "iat": time.time()}
			expire = datetime.utcnow() + timedelta(days=7)
			resp.set_cookie("session", session_token, httponly=True, samesite="Lax", expires=expire)
			return resp
	finally:
		conn.close()


@app.route("/api/login", methods=["POST"])  # JSON or form-encoded
def api_login():
	data = request.get_json(silent=True) or request.form
	username = (data.get("username") or "").strip().lower()
	password = data.get("password") or ""
	if not (username and password):
		return jsonify({"error": "missing_fields"}), 400
	conn = get_db_connection()
	try:
		user = get_user_by_username(conn, username)
		if not user or not verify_password(password, user["password_hash"]):
			return jsonify({"error": "invalid_credentials"}), 401
		resp = make_response(jsonify({"ok": True, "user_id": user["id"]}))
		session_token = uuid.uuid4().hex
		_sessions[session_token] = {"user_id": user["id"], "username": username, "iat": time.time()}
		expire = datetime.utcnow() + timedelta(days=7)
		resp.set_cookie("session", session_token, httponly=True, samesite="Lax", expires=expire)
		return resp
	finally:
		conn.close()


@app.route("/api/survey", methods=["POST"])  # requires session
def api_survey():
	session_token = request.cookies.get("session")
	sess = _sessions.get(session_token)
	if not sess:
		return jsonify({"error": "unauthorized"}), 401
	data = request.get_json(silent=True) or request.form
	student_name = (data.get("student_name") or "").strip()
	student_id = (data.get("student_id") or "").strip()
	email = (data.get("email") or "").strip().lower()
	course = (data.get("course") or "").strip()
	year = data.get("year")
	feedback = (data.get("feedback") or "").strip()
	try:
		year_int = int(year)
	except Exception:
		return jsonify({"error": "invalid_year"}), 400
	if not all([student_name, student_id, email, course, feedback]):
		return jsonify({"error": "missing_fields"}), 400
	conn = get_db_connection()
	try:
		with conn:
			conn.execute(
				"""
				INSERT INTO surveys(user_id, student_name, student_id, email, course, year, feedback, created_at)
				VALUES(?,?,?,?,?,?,?,?)
				""",
				(
					sess["user_id"],
					student_name,
					student_id,
					email,
					course,
					year_int,
					feedback,
					datetime.utcnow().isoformat(),
				),
			)
		return jsonify({"ok": True})
	finally:
		conn.close()


# simple in-memory session store for demo
_sessions = {}


if __name__ == "__main__":
	configure_logging()
	init_db_schema()
	port = int(os.getenv("PORT", "8000"))
	app.run(host="0.0.0.0", port=port)