import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import socket
import requests


class ApiSession:
    def __init__(self):
        self.token = None
        self.verify_ssl = True

    def _check_host(self, host: str, use_https: bool) -> bool:
        port = 443 if use_https else 80
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    def login(self, host, username, password, use_https, verify_ssl, raw_out, readable_out):
        scheme = "https" if use_https else "http"
        self.verify_ssl = verify_ssl
        if not self._check_host(host, use_https):
            raw_out.delete(1.0, tk.END)
            readable_out.delete(1.0, tk.END)
            raw_out.insert(tk.END, f"Host {host} is unreachable")
            self.token = None
            return
        try:
            resp = requests.post(
                f"{scheme}://{host.rstrip('/')}/api/login",
                json={"username": username, "password": password},
                timeout=5,
                verify=self.verify_ssl,
            )
        except requests.exceptions.SSLError:
            if self.verify_ssl:
                raw_out.delete(1.0, tk.END)
                raw_out.insert(tk.END, "SSL verification failed, retrying without verification...\n")
                resp = requests.post(
                    f"{scheme}://{host.rstrip('/')}/api/login",
                    json={"username": username, "password": password},
                    timeout=5,
                    verify=False,
                )
                self.verify_ssl = False
            else:
                raise
        try:
            resp.raise_for_status()
            self.token = resp.json().get("data", {}).get("token")
            if not self.token:
                raise RuntimeError("No token in response")
            raw_out.delete(1.0, tk.END)
            readable_out.delete(1.0, tk.END)
            readable_out.insert(tk.END, "Login successful")
        except Exception as e:
            self.token = None
            raw_out.delete(1.0, tk.END)
            readable_out.delete(1.0, tk.END)
            raw_out.insert(tk.END, str(e))

    def request(self, host, method, path, payload, use_https):
        if not self.token:
            raise RuntimeError("Not authenticated")
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{host.rstrip('/')}/api/{path.lstrip('/')}"
        headers = {"Authorization": f"Bearer {self.token}"}
        data = json.loads(payload) if payload else None
        response = requests.request(method, url, headers=headers, json=data, timeout=5, verify=self.verify_ssl)
        response.raise_for_status()
        return response


def main():
    session = ApiSession()

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
    method_var = tk.StringVar(value="GET")
    method_combo = ttk.Combobox(root, textvariable=method_var, values=["GET", "POST", "PUT", "DELETE"], width=17)
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

    def login_cmd():
        session.login(
            host_var.get(),
            user_var.get(),
            pass_var.get(),
            https_var.get(),
            verify_var.get(),
            raw_output,
            readable_output,
        )
        verify_var.set(session.verify_ssl)

    def send_cmd():
        try:
            session.verify_ssl = verify_var.get()
            resp = session.request(
                host_var.get(),
                method_var.get(),
                path_var.get(),
                payload_text.get(1.0, tk.END).strip(),
                https_var.get(),
            )
            raw_output.delete(1.0, tk.END)
            readable_output.delete(1.0, tk.END)
            raw_output.insert(tk.END, resp.text)
            try:
                parsed = resp.json()
                readable_output.insert(tk.END, json.dumps(parsed, indent=2, ensure_ascii=False))
            except ValueError:
                readable_output.insert(tk.END, resp.text)
        except Exception as e:
            raw_output.delete(1.0, tk.END)
            readable_output.delete(1.0, tk.END)
            raw_output.insert(tk.END, str(e))

    ttk.Button(root, text="Login", command=login_cmd).grid(row=8, column=0, pady=5)
    ttk.Button(root, text="Send", command=send_cmd).grid(row=8, column=1, pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
