"""
Diagnostic non intrusif de l'environnement serveur ThreatWatch.

Le script n'arrete aucun processus. Il indique simplement si les ports usuels
sont libres et, si un serveur repond, teste /health.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import get_safe_database_url, test_database_connection  # noqa: E402


PORTS = [8000, 8001, 8010]


def main() -> int:
    print(f"Diagnostic serveur ThreatWatch avec DATABASE_URL={get_safe_database_url()}")
    test_database_connection()

    for port in PORTS:
        if is_port_open("127.0.0.1", port):
            print(f"Port {port}: occupe")
            check_health(port)
        else:
            print(f"Port {port}: libre")

    print("Commande conseillee:")
    print(r".\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8001")
    print("SERVER ENVIRONMENT CHECK: OK")
    return 0


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def check_health(port: int) -> None:
    try:
        with urlopen(f"http://127.0.0.1:{port}/health", timeout=1.5) as response:
            body = response.read().decode("utf-8", errors="replace")
        print(f"  /health: HTTP {response.status} {body}")
    except URLError:
        print("  /health: indisponible sur ce port")
    except TimeoutError:
        print("  /health: timeout")


if __name__ == "__main__":
    raise SystemExit(main())
