import argparse
import json
import requests


class TeltonikaClient:
    """Simple client for Teltonika routers using ubus HTTP API."""

    def __init__(self, host: str, username: str, password: str, timeout: float = 5.0):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.token = None

    def _url(self) -> str:
        return f"http://{self.host}/ubus"

    def login(self) -> None:
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
        resp = self.session.post(self._url(), json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        self.token = data.get("result", [None, {}])[1].get("ubus_rpc_session")
        if not self.token:
            raise RuntimeError("Failed to obtain session token")

    def call(self, obj: str, method: str, params: dict) -> dict:
        if not self.token:
            self.login()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [self.token, obj, method, params],
        }
        resp = self.session.post(self._url(), json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send API requests to Teltonika device")
    parser.add_argument("host", help="Device IP or hostname")
    parser.add_argument("username", help="Login username")
    parser.add_argument("password", help="Login password")
    parser.add_argument("object", help="Ubus object name")
    parser.add_argument("method", help="Ubus method name")
    parser.add_argument("params", help="JSON string with parameters for the call")

    args = parser.parse_args()

    try:
        params = json.loads(args.params)
    except json.JSONDecodeError:
        print("Invalid JSON for params")
        return

    client = TeltonikaClient(args.host, args.username, args.password)
    try:
        response = client.call(args.object, args.method, params)
        print(json.dumps(response, indent=2))
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
