import argparse
import json
import socket
import re
import requests
from requests.exceptions import SSLError


class TeltonikaAPI:
    """Simple client for Teltonika HTTP API using token based authentication."""

    def __init__(self, host: str, username: str, password: str, *, use_https: bool = False, verify_ssl: bool = True, timeout: float = 5.0) -> None:
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.scheme = "https" if use_https else "http"
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token: str | None = None

    def _check_host(self) -> bool:
        """Return True if host is reachable on the expected port."""
        port = 443 if self.scheme == "https" else 80
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def _base_url(self) -> str:
        return f"{self.scheme}://{self.host}/api"

    def login(self) -> None:
        if not self._check_host():
            raise RuntimeError(f"Host {self.host} is unreachable")
        url = f"{self._base_url()}/login"
        try:
            resp = self.session.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except SSLError:
            if self.verify_ssl:
                resp = self.session.post(
                    url,
                    json={"username": self.username, "password": self.password},
                    timeout=self.timeout,
                    verify=False,
                )
                self.verify_ssl = False
                self.session.verify = False
            else:
                raise
        resp.raise_for_status()
        data = resp.json()
        self.token = data.get("data", {}).get("token")
        if not self.token:
            raise RuntimeError("Failed to obtain token")

    def request(self, method: str, path: str, data: str | None = None) -> requests.Response:
        if not self.token:
            self.login()
        url = f"{self._base_url()}/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self.token}"}
        json_payload = None
        if data:
            text = data.strip()
            if (
                (text.startswith("'") and text.endswith("'"))
                or (text.startswith('"') and text.endswith('"'))
            ):
                text = text[1:-1]
            try:
                json_payload = json.loads(text)
            except json.JSONDecodeError:
                cleaned = re.sub(r",\s*([}\]])", r"\1", text)
                try:
                    json_payload = json.loads(cleaned)
                except json.JSONDecodeError:
                    try:
                        import ast

                        json_payload = ast.literal_eval(cleaned)
                        if not isinstance(json_payload, (dict, list)):
                            raise ValueError
                    except Exception:
                        cleaned = cleaned.replace("'", '"')
                        try:
                            json_payload = json.loads(cleaned)
                        except json.JSONDecodeError:
                            json_payload = None
                            text = cleaned
                            headers.setdefault("Content-Type", "application/json")
        if json_payload is not None:
            response = self.session.request(
                method.upper(), url, headers=headers, json=json_payload, timeout=self.timeout
            )
        else:
            response = self.session.request(
                method.upper(), url, headers=headers, data=text, timeout=self.timeout
            )
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise requests.HTTPError(f"{e}\n{response.text}") from None
        return response


def main() -> None:
    parser = argparse.ArgumentParser(description="Send HTTP API requests to Teltonika device")
    parser.add_argument("host", help="Device IP or hostname")
    parser.add_argument("username", help="Login username")
    parser.add_argument("password", help="Login password")
    parser.add_argument("method", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method")
    parser.add_argument("path", help="API path, e.g. /wireguard/config")
    parser.add_argument("--data", help="JSON payload for POST/PUT", default=None)
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")

    args = parser.parse_args()

    client = TeltonikaAPI(
        args.host,
        args.username,
        args.password,
        use_https=args.https,
        verify_ssl=not args.no_verify,
    )

    try:
        resp = client.request(args.method, args.path, args.data)
        try:
            print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
        except ValueError:
            print(resp.text)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
