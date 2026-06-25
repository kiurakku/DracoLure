import os

from flask import Flask, jsonify, request
import psycopg2
from prometheus_client import start_http_server, Summary

app = Flask(__name__)

REQUEST_TIME = Summary("request_processing_seconds", "Time spent processing request")


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "db"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        database=os.environ.get("POSTGRES_DB", "honeypot"),
        user=os.environ.get("POSTGRES_USER", "honeypot"),
        password=os.environ.get("POSTGRES_PASSWORD", "honeypot_secret"),
    )


@app.route("/")
def hello_world():
    return "Honeypot Flask Server"


@app.route("/health")
def health():
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({"status": "ok"}), 200
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 503


@app.route("/attack", methods=["POST"])
@REQUEST_TIME.time()
def log_attack():
    data = request.get_json(force=True, silent=True) or {}
    attack_type = data.get("attack_type", "unknown")
    source_ip = data.get("source_ip", request.remote_addr or "0.0.0.0")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attacks (attack_type, source_ip, timestamp) VALUES (%s, %s, NOW())",
        (attack_type, source_ip),
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Attack logged successfully"}), 200


if __name__ == "__main__":
    start_http_server(8000)
    app.run(host="0.0.0.0", port=5000)
