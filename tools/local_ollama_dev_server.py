"""Lightweight local Ollama development & mock server for Entropy.

Listens on http://127.0.0.1:11434 and serves the 'k2-horizon:7b-q4' local model
for testing and development without requiring the full 1.6GB Ollama package.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ollama-dev-server")

MODEL_NAME = "k2-horizon:7b-q4"


class OllamaDevHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        logger.info("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:
        if self.path in ("/", "/api/version"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"Ollama is running\n")
        elif self.path == "/api/tags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = {
                "models": [
                    {
                        "name": MODEL_NAME,
                        "model": MODEL_NAME,
                        "modified_at": "2026-10-31T00:00:00Z",
                        "size": 4100000000,
                        "digest": "sha256:k2horizon7b4qmock0000000000000000000000000000",
                        "details": {
                            "format": "gguf",
                            "family": "k2",
                            "parameter_size": "7B",
                            "quantization_level": "Q4_K_M",
                        },
                    }
                ]
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req_data = json.loads(body.decode("utf-8"))
        except Exception:
            req_data = {}

        model = req_data.get("model", MODEL_NAME)
        messages = req_data.get("messages", [])
        user_content = ""
        for m in messages:
            if m.get("role") == "user":
                user_content = m.get("content", "")

        # Extract context if present in user prompt
        finding_meta = "finding"
        for line in user_content.splitlines():
            if "Rule ID:" in line:
                finding_meta = line.strip().replace("- ", "")
                break

        explanation_payload = {
            "summary": f"Local LLM ({model}) analysis for {finding_meta}",
            "why_it_matters": "The identified pattern introduces maintainability and security debt by diverging from architectural standards.",
            "evidence_explanation": "Deterministic evidence indicates an unchecked flow or unhandled boundary in the source code.",
            "architectural_impact": "Accumulated architectural debt increases review cognitive load and risks hidden runtime exceptions.",
            "remediation": "Refactor the flagged block to enforce explicit validation and structured exception handling.",
            "suggested_pattern": "# Recommended pattern\ntry:\n    # execute explicit validated contract\n    pass\nexcept SpecificException as err:\n    logger.error('Handled exception: %s', err)",
            "confidence": "high",
        }

        if self.path == "/api/chat":
            resp = {
                "model": model,
                "created_at": "2026-10-31T00:00:00Z",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(explanation_payload, indent=2),
                },
                "done": True,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        elif self.path in ("/v1/chat/completions", "/chat/completions"):
            resp = {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(explanation_payload, indent=2),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def run_server(port: int = 11434) -> None:
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, OllamaDevHandler)
    logger.info("Local Ollama server listening on http://127.0.0.1:%d (serving model: %s)", port, MODEL_NAME)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping local Ollama server...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    run_server(port)
