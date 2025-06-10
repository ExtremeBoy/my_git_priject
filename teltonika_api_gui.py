import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import requests


def send_request(
    host,
    username,
    password,
    method,
    path,
    payload,
    use_https,
    verify_ssl,
    raw_output,
    readable_output,
):
    """Send request to the router either via plain HTTP or UBUS call."""
    try:
        scheme = "https" if use_https else "http"
        if method.upper() == "UBUS":
            session = requests.Session()
            session.verify = verify_ssl
            login_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "call",
                "params": [
                    "00000000000000000000000000000000",
                    "session",
                    "login",
                    {"username": username, "password": password},
                ],
            }
            login_resp = session.post(
                f"{scheme}://{host}/ubus",
                json=login_payload,
                timeout=5,
            )
            login_resp.raise_for_status()
            token = login_resp.json().get("result", [None, {}])[1].get("ubus_rpc_session")
            if not token:
                raise RuntimeError("Failed to obtain session token")

            try:
                obj, ubus_method = path.strip("/").split("/", 1)
            except ValueError:
                raise ValueError("Path for UBUS must be in 'object/method' format")

            params = json.loads(payload) if payload else {}
            call_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "call",
                "params": [token, obj, ubus_method, params],
            }
            response = session.post(
                f"{scheme}://{host}/ubus",
                json=call_payload,
                timeout=5,
            )
        else:
            url = f"{scheme}://{host.rstrip('/')}/{path.lstrip('/')}"
            req_kwargs = {
                "auth": (username, password),
                "timeout": 5,
                "verify": verify_ssl,
            }
            if method.upper() == "GET":
                response = requests.get(url, **req_kwargs)
            elif method.upper() == "POST":
                data = payload.encode("utf-8") if payload else None
                response = requests.post(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"} if payload else None,
                    **req_kwargs,
                )
            elif method.upper() == "PUT":
                data = payload.encode("utf-8") if payload else None
                response = requests.put(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"} if payload else None,
                    **req_kwargs,
                )
            elif method.upper() == "DELETE":
                response = requests.delete(url, **req_kwargs)
            else:
                raw_output.delete(1.0, tk.END)
                readable_output.delete(1.0, tk.END)
                raw_output.insert(tk.END, f"Unsupported method: {method}")
                return

        raw_output.delete(1.0, tk.END)
        readable_output.delete(1.0, tk.END)
        raw_output.insert(tk.END, response.text)

        try:
            parsed = response.json()
            readable_output.insert(tk.END, json.dumps(parsed, indent=2, ensure_ascii=False))
        except ValueError:
            readable_output.insert(tk.END, response.text)
    except Exception as e:
        raw_output.delete(1.0, tk.END)
        readable_output.delete(1.0, tk.END)
        raw_output.insert(tk.END, str(e))


def main():
    root = tk.Tk()
    root.title("Teltonika API Client")

    tk.Label(root, text="IP address:").grid(row=0, column=0, sticky="e")
    host_var = tk.StringVar(value="192.168.1.1")
    tk.Entry(root, textvariable=host_var, width=20).grid(row=0, column=1)
    https_var = tk.BooleanVar(value=False)
    tk.Checkbutton(root, text="HTTPS", variable=https_var).grid(row=0, column=2, padx=5)
    verify_var = tk.BooleanVar(value=True)
    tk.Checkbutton(root, text="Verify SSL", variable=verify_var).grid(row=0, column=3, padx=5)

    tk.Label(root, text="Username:").grid(row=1, column=0, sticky="e")
    user_var = tk.StringVar(value="admin")
    tk.Entry(root, textvariable=user_var, width=20).grid(row=1, column=1)

    tk.Label(root, text="Password:").grid(row=2, column=0, sticky="e")
    pass_var = tk.StringVar(value="admin")
    tk.Entry(root, textvariable=pass_var, show="*", width=20).grid(row=2, column=1)

    tk.Label(root, text="Method:").grid(row=3, column=0, sticky="e")
    method_var = tk.StringVar(value="UBUS")
    method_combo = ttk.Combobox(root, textvariable=method_var, values=["UBUS", "GET", "POST", "PUT", "DELETE"], width=17)
    method_combo.grid(row=3, column=1)

    tk.Label(root, text="Path:").grid(row=4, column=0, sticky="e")
    path_var = tk.StringVar(value="/")
    tk.Entry(root, textvariable=path_var, width=20).grid(row=4, column=1)

    tk.Label(root, text="Payload (JSON for POST/PUT):").grid(row=5, column=0, sticky="ne")
    payload_text = scrolledtext.ScrolledText(root, width=40, height=5)
    payload_text.grid(row=5, column=1)

    tk.Label(root, text="Raw response:").grid(row=6, column=0, sticky="nw")
    raw_output = scrolledtext.ScrolledText(root, width=60, height=10)
    raw_output.grid(row=6, column=1, padx=5, pady=5)

    tk.Label(root, text="Readable response:").grid(row=7, column=0, sticky="nw")
    readable_output = scrolledtext.ScrolledText(root, width=60, height=10)
    readable_output.grid(row=7, column=1, padx=5, pady=5)

    send_btn = ttk.Button(
        root,
        text="Send",
        command=lambda: send_request(
            host_var.get(),
            user_var.get(),
            pass_var.get(),
            method_var.get(),
            path_var.get(),
            payload_text.get(1.0, tk.END).strip(),
            https_var.get(),
            verify_var.get(),
            raw_output,
            readable_output,
        ),
    )
    send_btn.grid(row=8, column=0, columnspan=2, pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
