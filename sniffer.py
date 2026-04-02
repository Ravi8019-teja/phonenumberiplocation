import tkinter as tk
from tkinter import messagebox, scrolledtext, Tk, PhotoImage
from scapy.all import *
import socket
import subprocess
import webbrowser
import base64
from PIL import Image, ImageTk
import io
import tempfile
import sys
import os
import time
import threading


class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("600x800")
        self.root.configure(bg="black")

        self.sniffing = False
        self.captured_packets = []
        self.stop_event = threading.Event()

        # Title
        tk.Label(self.root, text="Network Packets Sniffer",
                 bg="black", fg="white",
                 font=("Arial", 18, "bold")).pack(pady=5)

        # Image Placeholder
        self.img_label = tk.Label(self.root, bg="black")
        self.img_label.pack(pady=10)
        self.load_placeholder_image()

        # Filter Selection
        tk.Label(self.root, text="Select Filter",
                 bg="white", fg="black",
                 font=("Arial", 10)).pack(pady=5)

        self.filter_list = tk.Listbox(self.root, height=5, width=40, font=("Courier", 10))

        filters = ["All", "tcp port 80", "tcp port 443", "udp", "icmp"]

        for f in filters:
            self.filter_list.insert(tk.END, f)

        self.filter_list.select_set(0)
        self.filter_list.pack(pady=5)

        # Control Panel
        self.control_frame = tk.Frame(self.root, bg="#333333", padx=20, pady=20)
        self.control_frame.pack(fill="both", side="bottom", expand=True)

        self.start_btn = tk.Button(self.control_frame, text="Start Sniffing",
                                   bg="red", fg="white", width=15,
                                   font=("Arial", 12, "bold"),
                                   command=self.start_sniffing)
        self.start_btn.grid(row=0, column=1, pady=10)

        self.stop_btn = tk.Button(self.control_frame, text="Stop Sniffing",
                                  bg="red", fg="white", width=15,
                                  font=("Arial", 12, "bold"),
                                  command=self.stop_sniffing)
        self.stop_btn.grid(row=1, column=1, pady=10)

        tk.Button(self.control_frame, text="View Logs",
                  bg="red", fg="white", width=12,
                  command=self.view_logs).grid(row=0, column=0, padx=10)

        tk.Button(self.control_frame, text="Captured Data",
                  bg="red", fg="white", width=12,
                  command=self.view_data_stats).grid(row=0, column=2, padx=10)

        tk.Button(self.control_frame, text="Project Info",
                  bg="red", fg="white", width=12,
                  command=self.open_info).grid(row=1, column=0, padx=10)

    # ---------------- LOGIC FUNCTIONS ----------------

    def load_placeholder_image(self):
        try:
            img = Image.new('RGB', (250, 180), color=(0, 100, 255))
            self.photo = ImageTk.PhotoImage(img)
            self.img_label.config(image=self.photo)
        except Exception as e:
            print(f"Image load error: {e}")

    def open_info(self):
        """Generates a Project Info page"""
        html_content = """
        <html>
        <head>
        <style>
        body {font-family: Arial; margin:40px;}
        table {border-collapse: collapse; width:100%;}
        th,td {border:1px solid #ddd; padding:10px;}
        </style>
        </head>

        <body>

        <h1>Project Information</h1>

        <table>
        <tr><th>Project Name</th><td>Sniffing Network to Identify Malicious Data</td></tr>
        <tr><th>Description</th><td>Sniffing Network Traffic</td></tr>
        <tr><th>Start Date</th><td>01-March-2026</td></tr>
        <tr><th>End Date</th><td>31-March-2026</td></tr>
        <tr><th>Status</th><td>Completed</td></tr>
        </table>

        <h2>Company</h2>

        <table>
        <tr><th>Name</th><td>Supraja Technologies</td></tr>
        <tr><th>Email</th><td>contact@suprajatechnologies.com</td></tr>
        </table>

        </body>
        </html>
        """

        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as f:
            f.write(html_content)
            temp_path = f.name

        webbrowser.open(f"file://{os.path.realpath(temp_path)}")

    def packet_callback(self, packet):

        if self.sniffing:

            summary = packet.summary()

            if packet.haslayer(Raw):

                payload = packet[Raw].load.decode(errors='ignore')

                keywords = ["user", "pass", "login", "pwd"]

                if any(k in payload.lower() for k in keywords):
                    summary = f"[!] ALERT: {summary} | DATA: {payload[:50]}..."

            self.captured_packets.append(summary)

    def sniff_packets(self, filter_val):

        bpf_filter = "" if filter_val == "All" else filter_val

        sniff(filter=bpf_filter,
              prn=self.packet_callback,
              store=False,
              stop_filter=lambda x: not self.sniffing)

    def start_sniffing(self):

        if not self.sniffing:

            self.sniffing = True
            self.captured_packets = []

            selected = self.filter_list.get(tk.ACTIVE)

            self.sniff_thread = threading.Thread(
                target=self.sniff_packets,
                args=(selected,),
                daemon=True)

            self.sniff_thread.start()

            messagebox.showinfo("Sniffer", f"Started capturing: {selected}")

    def stop_sniffing(self):

        self.sniffing = False

        messagebox.showinfo("Sniffer", "Capture Stopped.")

    def view_logs(self):

        log_win = tk.Toplevel(self.root)
        log_win.title("Packet Logs")

        txt = scrolledtext.ScrolledText(log_win,
                                        width=80,
                                        height=30,
                                        bg="black",
                                        fg="green")

        txt.pack()

        for p in self.captured_packets:
            txt.insert(tk.END, p + "\n")

    def view_data_stats(self):

        count = len(self.captured_packets)

        messagebox.showinfo("Stats",
                            f"Total Packets Captured: {count}")


if __name__ == "__main__":

    root = tk.Tk()

    app = NetworkSnifferApp(root)

    root.mainloop()