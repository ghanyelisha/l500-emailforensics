#!/usr/bin/env python3

import argparse
import importlib.util
import json
import os
import tempfile
import time
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from html_generator import generate_table_from_json

PROJECT_ROOT = Path(__file__).resolve().parent
ANALYZER_PATH = PROJECT_ROOT / "email-analyzer.py"
LOG_PATH = Path(r"e:\L500\Computer Frensics\Email Forensics Group Work\.cursor\debug.log")
RUN_ID = "post-fix"


def _log_debug(hypothesis_id, location, message, data):
    payload = {
        "sessionId": "debug-session",
        "runId": RUN_ID,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(payload) + "\n")
    except OSError:
        pass


def load_email_analyzer():
    spec = importlib.util.spec_from_file_location("email_analyzer", ANALYZER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EMAIL_ANALYZER = load_email_analyzer()

# region agent log
_log_debug(
    "H1",
    "web_app.py:36",
    "runtime_info",
    {"python": sys.version, "executable": sys.executable},
)
_log_debug(
    "H2",
    "web_app.py:42",
    "cgi_spec_check",
    {"cgi_spec": importlib.util.find_spec("cgi") is not None},
)
# endregion agent log


def _parse_multipart(content_type, body):
    boundary_token = "boundary="
    if boundary_token not in content_type:
        return None, None
    boundary = content_type.split(boundary_token, 1)[1].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary_bytes = ("--" + boundary).encode("utf-8")
    parts = body.split(boundary_bytes)
    for part in parts:
        if not part or part in (b"--\r\n", b"--"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if part.endswith(b"--"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        header_blob, payload = part.split(b"\r\n\r\n", 1)
        headers = {}
        for line in header_blob.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("utf-8", "ignore").lower()] = v.decode("utf-8", "ignore").strip()
        disposition = headers.get("content-disposition", "")
        if 'name="eml_file"' in disposition:
            filename = None
            for token in disposition.split(";"):
                token = token.strip()
                if token.startswith("filename="):
                    filename = token.split("=", 1)[1].strip().strip('"')
                    break
            return filename, payload
    return None, None


UPLOAD_PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.6.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <title>Email Forensics - Upload</title>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#"><i class="fa fa-envelope"></i> Email Forensics</a>
    </nav>
    <div class="container mt-4">
      <div class="row">
        <div class="col-md-8 offset-md-2">
          <div class="card">
            <div class="card-body">
              <h3 class="card-title text-center"><i class="fa-solid fa-upload"></i> Upload EML</h3>
              <p class="text-muted text-center mb-4">Upload a .eml file to run full analysis.</p>
              <form method="post" enctype="multipart/form-data">
                <div class="form-group">
                  <input type="file" class="form-control-file" name="eml_file" accept=".eml" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Analyze</button>
              </form>
            </div>
          </div>
          <p class="text-muted text-center mt-3">Reports are generated locally. No data is uploaded elsewhere.</p>
        </div>
      </div>
    </div>
  </body>
</html>
"""


def build_report_html(eml_bytes, original_name):
    mail_data = eml_bytes.decode("utf-8", errors="ignore").rstrip()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        tmp_file.write(eml_bytes)
        tmp_path = tmp_file.name

    try:
        app_data = {"Information": {}, "Analysis": {}}
        app_data["Information"]["Project"] = {
            "Name": "Email Forensics",
            "Url": "https://github.com/ghanyelisha/l500-emailforensics",
            "Version": "2.0",
        }
        app_data["Information"]["Scan"] = {
            "Filename": original_name,
            "Generated": datetime.now().strftime(EMAIL_ANALYZER.DATE_FORMAT),
        }

        headers = EMAIL_ANALYZER.get_headers(mail_data, True)
        app_data["Analysis"].update(headers)

        digests = EMAIL_ANALYZER.get_digests(mail_data, tmp_path, True)
        app_data["Analysis"].update(digests)

        links = EMAIL_ANALYZER.get_links(mail_data, True)
        app_data["Analysis"].update(links)

        attachments = EMAIL_ANALYZER.get_attachments(tmp_path, True)
        app_data["Analysis"].update(attachments)

        report_html = generate_table_from_json(app_data)
        return f"<!doctype html><html lang='en'>{report_html}</html>"
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


class UploadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(UPLOAD_PAGE.encode("utf-8"))

    def do_POST(self):
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get("content-type", "")
        # region agent log
        _log_debug(
            "H3",
            "web_app.py:132",
            "post_request_content_type",
            {"content_type": content_type},
        )
        # endregion agent log
        if "multipart/form-data" not in content_type:
            self.send_response(400)
            self.end_headers()
            return

        content_length = int(self.headers.get("content-length", "0"))
        # region agent log
        _log_debug(
            "H2",
            "web_app.py:174",
            "content_length",
            {"content_length": content_length},
        )
        # endregion agent log
        if content_length <= 0:
            self.send_response(400)
            self.end_headers()
            return

        body = self.rfile.read(content_length)
        filename, eml_bytes = _parse_multipart(content_type, body)
        # region agent log
        _log_debug(
            "H3",
            "web_app.py:189",
            "multipart_parse_result",
            {"filename": filename, "payload_size": len(eml_bytes) if eml_bytes else 0},
        )
        # endregion agent log

        if not filename or eml_bytes is None:
            self.send_response(400)
            self.end_headers()
            return

        original_name = os.path.basename(filename)
        if not original_name.lower().endswith(".eml"):
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Only .eml files are supported.")
            return

        report_html = build_report_html(eml_bytes, original_name)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(report_html.encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Email Forensics web uploader")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", default=8000, type=int, help="Port to bind (default: 8000)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), UploadHandler)
    print(f"Serving on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
