"""
Phase 13: Demo Lab

Local vulnerable Flask app dùng để test Context-Aware Fuzzer.

Chạy:
    python demo_lab.py

Server:
    http://localhost:5000

Endpoints:
    POST /api/login
        - Trả Bearer token demo-token

    GET /api/users?id=1
        - Endpoint chứa SQLi-like behavior, time-based SQLi-like và IDOR

    GET /api/search?q=test
        - Endpoint chứa reflected XSS

    GET /api/files?path=readme.txt
        - Endpoint chứa path traversal demo
"""

from flask import Flask, request, jsonify, make_response
from urllib.parse import unquote
import time


app = Flask(__name__)


DEMO_TOKEN = "demo-token"


USERS = {
    "1": {
        "id": 1,
        "user_id": 1,
        "username": "alice",
        "email": "alice@example.com",
        "role": "user",
        "owner_id": 1,
        "owner": "alice"
    },
    "2": {
        "id": 2,
        "user_id": 2,
        "username": "bob",
        "email": "bob@example.com",
        "role": "admin",
        "owner_id": 2,
        "owner": "bob"
    },
    "9999": {
        "id": 9999,
        "user_id": 9999,
        "username": "hidden-admin",
        "email": "hidden-admin@example.com",
        "role": "superadmin",
        "owner_id": 9999,
        "owner": "system"
    }
}


FILES = {
    "readme.txt": "This is a normal public file.",
    "notes.txt": "Normal notes file."
}


def require_auth():
    """
    Demo auth check.

    Nếu muốn test auth_enabled=true trong fuzzer,
    request cần header:

        Authorization: Bearer demo-token
    """

    auth_header = request.headers.get("Authorization", "")

    if auth_header == f"Bearer {DEMO_TOKEN}":
        return True

    return False


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "Context-Aware Fuzzer Demo Lab is running",
        "endpoints": [
            "POST /api/login",
            "GET /api/users?id=1",
            "GET /api/search?q=test",
            "GET /api/files?path=readme.txt",
            "GET /api/health"
        ]
    })


@app.route("/api/login", methods=["POST"])
def login():
    """
    Demo login endpoint.

    Body mẫu:
        {
            "username": "admin",
            "password": "admin123"
        }

    Response:
        {
            "access_token": "demo-token",
            "token_type": "Bearer"
        }
    """

    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "admin123":
        return jsonify({
            "access_token": DEMO_TOKEN,
            "token_type": "Bearer"
        })

    return jsonify({
        "error": "Invalid username or password"
    }), 401


@app.route("/api/users", methods=["GET"])
def get_user():
    """
    Vulnerable demo endpoint.

    Normal:
        GET /api/users?id=1

    SQLi-like:
        GET /api/users?id=1'
        GET /api/users?id=1 OR 1=1
        GET /api/users?id=1 UNION SELECT NULL --

    Time-based SQLi-like:
        GET /api/users?id=1 OR SLEEP(5)

    IDOR:
        GET /api/users?id=2
        GET /api/users?id=9999
    """

    # Bật đoạn này nếu muốn test auth_enabled=true:
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    user_id = request.args.get("id", "1")
    lowered = user_id.lower()

    # Time-based SQLi markers, khớp với deep_payloads
    time_based_markers = [
        "sleep(5)",
        "pg_sleep(5)",
        "waitfor delay",
        "dbms_pipe.receive_message"
    ]

    if any(marker in lowered for marker in time_based_markers):
        time.sleep(5)
        return jsonify({
            "result": "Delayed response caused by user-controlled input",
            "query": user_id,
            "evidence": "time_based_sql_injection_candidate"
        })

    # SQLi markers, khớp với light/deep payloads
    sql_error_markers = [
        "'",
        "\"",
        "`",
        " or ",
        " and ",
        "union",
        "order by",
        "--",
        "#",
        "/*",
        "extractvalue",
        "updatexml",
        "cast(",
        "convert(",
        "information_schema",
        "select"
    ]

    if any(marker in lowered for marker in sql_error_markers):
        response = make_response(
            "SQL syntax error near user input. "
            "You have an error in your SQL syntax near: %s"
            % user_id,
            500
        )
        response.headers["Content-Type"] = "text/html"
        return response

    user = USERS.get(user_id)

    if not user:
        return jsonify({
            "error": "User not found"
        }), 404

    # IDOR chủ đích:
    # Không kiểm tra user hiện tại có quyền xem object này không.
    return jsonify({
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "owner_id": user["owner_id"],
        "owner": user["owner"]
    })


@app.route("/api/search", methods=["GET"])
def search():
    """
    Reflected XSS demo endpoint.

    Normal:
        GET /api/search?q=hello

    XSS reflection:
        GET /api/search?q=<xss-test>
        GET /api/search?q=<script>alert(1)</script>
    """

    q = request.args.get("q", "")

    html_body = f"""
    <html>
        <head>
            <title>Search</title>
        </head>
        <body>
            <h1>Search result</h1>
            <p>You searched for: {q}</p>
        </body>
    </html>
    """

    response = make_response(html_body, 200)
    response.headers["Content-Type"] = "text/html"
    return response


@app.route("/api/files", methods=["GET"])
def read_file():
    """
    Path traversal demo endpoint.

    Normal:
        GET /api/files?path=readme.txt

    Path Traversal:
        GET /api/files?path=../../../../../etc/passwd
        GET /api/files?path=..%2f..%2fetc%2fpasswd
        GET /api/files?path=..\\..\\windows\\win.ini
    """

    path = request.args.get("path", "readme.txt")

    # Decode nhiều lần để bắt cả encoded và double-encoded payload
    decoded_once = unquote(path)
    decoded_twice = unquote(decoded_once)

    lowered = decoded_twice.lower()

    traversal_markers = [
        "../",
        "..\\",
        "etc/passwd",
        "etc/hosts",
        "proc/self/environ",
        "proc/version",
        "win.ini",
        "system.ini",
        "boot.ini",
        "windows\\system32\\drivers\\etc\\hosts",
        "web-inf",
        ".env",
        "application.properties",
        "application.yml",
        "appsettings.json",
        "package.json",
        "file://"
    ]

    if any(marker in lowered for marker in traversal_markers):

        # Linux-like evidence
        if "etc/passwd" in lowered or "proc/" in lowered or ".env" in lowered:
            response = make_response(
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "DB_HOST=localhost\n"
                "DB_USER=demo\n"
                "DB_PASSWORD=demo_password\n"
                "SECRET_KEY=demo_secret\n",
                200
            )
            response.headers["Content-Type"] = "text/plain"
            return response

        # Windows-like evidence
        if "win.ini" in lowered or "system.ini" in lowered or "boot.ini" in lowered:
            response = make_response(
                "[extensions]\n"
                "[fonts]\n"
                "[mci extensions]\n"
                "[boot loader]\n"
                "for 16-bit app support\n",
                200
            )
            response.headers["Content-Type"] = "text/plain"
            return response

        # Java/Spring/.NET/Node config-like evidence
        response = make_response(
            "server.port=8080\n"
            "spring.datasource.url=jdbc:mysql://localhost:3306/demo\n"
            "ConnectionStrings:DefaultConnection=Server=localhost\n"
            "\"scripts\": {}\n"
            "\"dependencies\": {}\n",
            200
        )
        response.headers["Content-Type"] = "text/plain"
        return response

    content = FILES.get(path)

    if content is None:
        return jsonify({
            "error": "File not found"
        }), 404

    return jsonify({
        "path": path,
        "content": content
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


if __name__ == "__main__":
    print(" Demo Lab running on http://localhost:5000")
    print(" Press CTRL+C to stop")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )