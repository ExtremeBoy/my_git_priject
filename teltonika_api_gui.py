import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import socket
import re
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
        json_payload = None
        if payload:
            try:
                json_payload = json.loads(payload)
            except json.JSONDecodeError:
                cleaned = re.sub(r",\s*([}\]])", r"\1", payload)
                try:
                    json_payload = json.loads(cleaned)
                except json.JSONDecodeError:
                    cleaned = cleaned.replace("'", '"')
                    try:
                        json_payload = json.loads(cleaned)
                    except json.JSONDecodeError:
                        headers.setdefault("Content-Type", "application/json")
                        json_payload = None
        if json_payload is not None:
            response = requests.request(
                method, url, headers=headers, json=json_payload, timeout=5, verify=self.verify_ssl
            )
        else:
            response = requests.request(
                method, url, headers=headers, data=payload, timeout=5, verify=self.verify_ssl
            )
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise requests.HTTPError(f"{e}\n{response.text}") from None
        return response


def main():
    session = ApiSession()

    root = tk.Tk()
    root.title("Teltonika API Client")
    root.geometry("800x600")
    root.minsize(600, 400)
    root.resizable(True, True)
    root.columnconfigure(1, weight=1)
    root.rowconfigure(5, weight=1)
    root.rowconfigure(6, weight=1)
    root.rowconfigure(7, weight=1)

    host_history = []
    path_history = []

    def update_history(history, value, combo, limit=5):
        value = value.strip()
        if not value:
            return
        if value in history:
            history.remove(value)
        history.insert(0, value)
        del history[limit:]
        combo['values'] = history

    tk.Label(root, text="IP address:").grid(row=0, column=0, sticky="e")
    host_var = tk.StringVar(value="192.168.1.1")
    host_combo = ttk.Combobox(root, textvariable=host_var, values=host_history, width=20)
    host_combo.grid(row=0, column=1, sticky="ew", padx=(0,5))

    tk.Label(root, text="Username:").grid(row=1, column=0, sticky="e")
    user_var = tk.StringVar(value="admin")
    tk.Entry(root, textvariable=user_var, width=20).grid(row=1, column=1, sticky="ew", padx=(0,5))

    tk.Label(root, text="Password:").grid(row=2, column=0, sticky="e")
    pass_var = tk.StringVar()
    tk.Entry(root, textvariable=pass_var, show="*", width=20).grid(row=2, column=1, sticky="ew", padx=(0,5))
    login_btn = ttk.Button(root, text="Login", command=login_cmd)
    login_btn.grid(row=2, column=2, padx=5, pady=5)

    tk.Label(root, text="Method:").grid(row=3, column=0, sticky="e")
    method_var = tk.StringVar(value="GET")
    method_combo = ttk.Combobox(root, textvariable=method_var, values=["GET", "POST", "PUT", "DELETE"], width=17)
    method_combo.grid(row=3, column=1, sticky="w")

    tk.Label(root, text="Path:").grid(row=4, column=0, sticky="e")
    path_var = tk.StringVar(value="/")
    path_combo = ttk.Combobox(root, textvariable=path_var, values=path_history, width=20)
    path_combo.grid(row=4, column=1, sticky="ew", padx=(0,5))

    tk.Label(root, text="Payload (JSON for POST/PUT):").grid(row=5, column=0, sticky="ne")
    payload_text = scrolledtext.ScrolledText(root, width=40, height=5)
    payload_text.grid(row=5, column=1, sticky="nsew", padx=(0,5))

    https_var = tk.BooleanVar(value=False)
    verify_var = tk.BooleanVar(value=True)

    tk.Label(root, text="Raw response:").grid(row=6, column=0, sticky="nw")
    raw_output = scrolledtext.ScrolledText(root, width=60, height=10)
    raw_output.grid(row=6, column=1, padx=5, pady=5, sticky="nsew")

    tk.Label(root, text="Readable response:").grid(row=7, column=0, sticky="nw")
    readable_output = scrolledtext.ScrolledText(root, width=60, height=10)
    readable_output.grid(row=7, column=1, padx=5, pady=5, sticky="nsew")

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
        update_history(host_history, host_var.get(), host_combo)

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
            update_history(host_history, host_var.get(), host_combo)
            update_history(path_history, path_var.get(), path_combo)
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

    send_btn = ttk.Button(root, text="Send", command=send_cmd)
    send_btn.grid(row=8, column=1, pady=5, sticky="w")

    tk.Checkbutton(root, text="HTTPS", variable=https_var).grid(row=9, column=0, padx=5, sticky="w")
    tk.Checkbutton(root, text="Verify SSL", variable=verify_var).grid(row=9, column=1, sticky="w")

    root.mainloop()


if __name__ == "__main__":
    main()
