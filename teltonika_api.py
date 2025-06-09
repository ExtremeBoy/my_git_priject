import argparse
import json
import requests


class TeltonikaClient:
    """Client for Teltonika routers using the Ubus HTTPS API.

    The class provides basic login and command execution helpers and prints
    detailed information about each request and response so the user can see
    exactly what the router returns.
    """

    def __init__(self, host: str, username: str, password: str, timeout: float = 5.0, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.token = None

    def _url(self) -> str:
        return f"https://{self.host}/ubus"

    def login(self) -> None:
        scheme = "https"
        print(f"Connecting to {self.host} via {scheme.upper()} as '{self.username}'...")
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [
                "00000000000000000000000000000000",
                "session",
                "login",
                {
                    "username": self.username,
                    "password": self.password,
                },
            ],
        }
        resp = self.session.post(
            self._url(), json=payload, timeout=self.timeout, verify=self.verify_ssl
        )
        print(f"Login HTTP {resp.status_code}")
        resp.raise_for_status()
        print("Raw login response:")
        print(resp.text)
        data = resp.json()
        self.token = data.get("result", [None, {}])[1].get("ubus_rpc_session")
        if not self.token:
            raise RuntimeError("Failed to obtain session token")
        print("Session token obtained")

    def call(self, obj: str, method: str, params: dict) -> str:
        if not self.token:
            self.login()
        print(
            f"Sending command: object='{obj}', method='{method}', params={json.dumps(params)}"
        )
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [self.token, obj, method, params],
        }
        resp = self.session.post(
            self._url(), json=payload, timeout=self.timeout, verify=self.verify_ssl
        )
        print(f"Command HTTP {resp.status_code}")
        resp.raise_for_status()
        print("Raw command response:")
        print(resp.text)
        return resp.text


def main() -> None:
    parser = argparse.ArgumentParser(description="Send API requests to Teltonika device")
    parser.add_argument("host", help="Device IP or hostname")
    parser.add_argument("username", help="Login username")
    parser.add_argument("password", help="Login password")
    parser.add_argument("object", help="Ubus object name")
    parser.add_argument("method", help="Ubus method name")
    parser.add_argument("params", help="JSON string with parameters for the call")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify the router's SSL certificate",
    )

    args = parser.parse_args()

    try:
        params = json.loads(args.params)
    except json.JSONDecodeError:
        print("Invalid JSON for params")
        return

    client = TeltonikaClient(
        args.host, args.username, args.password, verify_ssl=args.verify_ssl
    )
    try:
        client.call(args.object, args.method, params)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
