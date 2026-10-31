"""Command-line entry point: ``strix --port 8000``."""
from __future__ import annotations

import argparse
import json
import logging

import uvicorn

from strix.config import Settings


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {"time": self.formatTime(record), "level": record.levelname,
                 "logger": record.name, "message": record.getMessage()}
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="strix", description="Strix assessment server")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1; use 0.0.0.0 behind a firewall/proxy)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true", help="auto-reload (development only)")
    args = parser.parse_args(argv)

    settings = Settings.from_env()
    handler = logging.StreamHandler()
    handler.setFormatter(
        _JsonFormatter() if settings.log_format == "json"
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=settings.log_level, handlers=[handler])
    # proxy_headers=False: STRIX_TRUSTED_PROXIES is the single authority on which
    # peers may supply X-Forwarded-For, so uvicorn must not rewrite client
    # addresses on its own (a local caller could otherwise spoof its identity).
    # timeout_graceful_shutdown caps SIGTERM handling: in-flight requests and the
    # worker's cancellation sweep get 30s, then the process exits so systemd or a
    # container runtime never waits forever on a wedged connection.
    uvicorn.run("strix.api.app:app", host=args.host, port=args.port, reload=args.reload,
                proxy_headers=False, timeout_graceful_shutdown=30)


if __name__ == "__main__":
    main()
