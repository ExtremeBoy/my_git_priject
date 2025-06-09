import tkinter as tk
from tkinter import ttk
import threading
from find_devices import scan_network


def start_scan(network, prefix, output_widget, button):
    def task():
        button.config(state='disabled')
        results = scan_network(network.get(), prefix.get())
        output_widget.delete(1.0, tk.END)
        if not results:
            output_widget.insert(tk.END, "No devices found\n")
        else:
            for ip, mac, hostname in results:
                if not hostname:
                    hostname = "unknown"
                output_widget.insert(tk.END, f"{ip} - {mac} - {hostname}\n")
        button.config(state='normal')

    threading.Thread(target=task, daemon=True).start()


def main():
    root = tk.Tk()
    root.title("Device Finder")

    tk.Label(root, text="Network:").grid(row=0, column=0, sticky="e")
    network_var = tk.StringVar(value="192.168.1.0/24")
    tk.Entry(root, textvariable=network_var, width=20).grid(row=0, column=1)

    tk.Label(root, text="MAC prefix:").grid(row=1, column=0, sticky="e")
    prefix_var = tk.StringVar(value="00:11:22")
    tk.Entry(root, textvariable=prefix_var, width=20).grid(row=1, column=1)

    text = tk.Text(root, width=40, height=10)
    text.grid(row=3, column=0, columnspan=2, pady=5)

    scan_button = ttk.Button(
        root,
        text="Scan",
        command=lambda: start_scan(network_var, prefix_var, text, scan_button),
    )
    scan_button.grid(row=2, column=0, columnspan=2, pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
