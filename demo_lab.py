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
        - Endpoint chứa SQLi-like behavior và IDOR

    GET /api/search?q=test
        - Endpoint chứa reflected XSS

    GET /api/files?path=readme.txt
        - Endpoint chứa path traversal demo

Lưu ý:
- Đây là app demo local cố ý có lỗi.
- Không deploy public.
"""

from flask import Flask, request, jsonify, make_response
import time


app = Flask(__name__)


DEMO_TOKEN = "demo-token"


USERS = {
    "1": {
        "id": 1,
        "username": "alice",
        "role": "user",
        "owner": "alice"
    },
    "2": {
        "id": 2,
        "username": "bob",
        "role": "admin",
        "owner": "bob"
    },
    "9999": {
        "id": 9999,
        "username": "hidden-admin",
        "role": "superadmin",
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

    Nếu bạn muốn test auth_enabled=true trong fuzzer,
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
            "GET /api/files?path=readme.txt"
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
            "access_token": "demo-token"
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

    Test bình thường:
        GET /api/users?id=1

    SQLi-like:
        GET /api/users?id=1'
        -> Trả SQL syntax error giả lập

    Time-based SQLi-like:
        GET /api/users?id=1 OR SLEEP(5)
        -> Delay 5 giây

    IDOR:
        GET /api/users?id=2
        -> Trả user khác mà không kiểm tra quyền object-level
    """

    # Bật đoạn này nếu muốn bắt buộc auth:
    # if not require_auth():
    #     return jsonify({"error": "Unauthorized"}), 401

    user_id = request.args.get("id", "1")

    lowered = user_id.lower()

    if "sleep(5)" in lowered:
        time.sleep(5)
        return jsonify({
            "id": user_id,
            "result": "Delayed response caused by user-controlled input"
        })

    sql_error_markers = [
        "'",
        "\"",
        " or ",
        " and ",
        "union",
        "--"
    ]

    if any(marker in lowered for marker in sql_error_markers):
        response = make_response(
            "SQL syntax error near user input in query: SELECT * FROM users WHERE id = '%s'"
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
    return jsonify(user)


@app.route("/api/search", methods=["GET"])
def search():
    """
    Reflected XSS demo endpoint.

    Test bình thường:
        GET /api/search?q=hello

    XSS reflection:
        GET /api/search?q=<xss-test>
        -> Reflect lại payload trong HTML response
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

    Test bình thường:
        GET /api/files?path=readme.txt

    Path traversal:
        GET /api/files?path=../../../../../etc/passwd
        -> Trả nội dung giả lập /etc/passwd
    """

    path = request.args.get("path", "readme.txt")

    traversal_markers = [
        "../",
        "..\\",
        "%2e%2e",
        "etc/passwd",
        "win.ini"
    ]

    lowered = path.lower()

    if any(marker in lowered for marker in traversal_markers):
        response = make_response(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
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
    print("[+] Demo Lab running on http://localhost:5000")
    print("[+] Press CTRL+C to stop")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )