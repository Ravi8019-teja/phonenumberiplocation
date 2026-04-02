import tkinter as tk
from datetime import datetime
import threading
import time
import os
from PIL import ImageGrab

logging = False
log_file = "activity_log.txt"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {message}\n")

def start_logging():
    global logging
    logging = True
    status_label.config(text="Status: Running")
    log_event("Logging started")
    threading.Thread(target=logger_loop).start()

def stop_logging():
    global logging
    logging = False
    status_label.config(text="Status: Stopped")
    log_event("Logging stopped")

def logger_loop():
    while logging:
        log_event("Program active")
        time.sleep(5)

def capture_screenshot():
    folder = "screenshots"
    os.makedirs(folder, exist_ok=True)

    filename = datetime.now().strftime("%Y%m%d_%H%M%S") + ".png"
    path = os.path.join(folder, filename)

    screenshot = ImageGrab.grab()
    screenshot.save(path)

    log_event(f"Screenshot captured: {path}")
    status_label.config(text="Screenshot Saved")

# GUI
root = tk.Tk()
root.title("Cybersecurity Activity Logger Lab")
root.geometry("400x300")

title = tk.Label(root, text="Activity Logger Tool", font=("Arial", 16))
title.pack(pady=10)

start_btn = tk.Button(root, text="Start Logging", command=start_logging, width=20)
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="Stop Logging", command=stop_logging, width=20)
stop_btn.pack(pady=5)

screen_btn = tk.Button(root, text="Capture Screenshot", command=capture_screenshot, width=20)
screen_btn.pack(pady=5)

status_label = tk.Label(root, text="Status: Stopped")
status_label.pack(pady=20)

root.mainloop()