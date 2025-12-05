import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import random
import time
import threading
from datetime import datetime
import serial
import serial.tools.list_ports
from PIL import Image, ImageTk
import requests
import csv
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# ================== PUSHOVER (PHONE NOTIFICATIONS) ==================
PUSHOVER_USER = "u4jnte1i7gvjdcr72qgu64y8ajv7tn"
PUSHOVER_TOKEN = "ayn3r32ddzgfjpmxdlykajbeew2ibu"

def send_phone_alert(message):
    try:
        resp = requests.post(
            "https://api.pushover.net/1/messages.json",
            data={
                "token": PUSHOVER_TOKEN,
                "user": PUSHOVER_USER,
                "message": message,
                "title": "Smart Grid Alert",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            log_event(f"Phone Notification Sent: {message}", "green")
        else:
            log_event(f"Phone Notification Failed ({resp.status_code}): {resp.text}", "red")
    except Exception as e:
        log_event(f"Phone Notification Error: {e}", "red")

# ================== LOGGING FUNCTION + HISTORY ==================
event_history = []
usage_history = []

def log_event(event, color="black"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_text = f"{timestamp} - {event}\n"

    with open("smart_grid_log.txt", "a") as log_file:
        log_file.write(log_text)

    event_history.append((timestamp, event, color))
    append_log_to_gui(log_text, color)

def append_log_to_gui(log_text, color):
    if log_box:
        log_box.config(state=tk.NORMAL)
        log_box.insert(tk.END, log_text)
        log_box.tag_add(color, f"end-{len(log_text)}c", "end")
        log_box.tag_config(color, foreground=color)
        log_box.see(tk.END)
        log_box.config(state=tk.DISABLED)

def show_history():
    history_win = tk.Toplevel(root)
    history_win.title("Event History")
    history_win.geometry("600x400")

    history_box = scrolledtext.ScrolledText(history_win, width=70, height=20, state=tk.NORMAL)
    history_box.pack(pady=10, padx=10, fill="both", expand=True)

    for ts, event, color in event_history:
        line = f"{ts} - {event}\n"
        history_box.insert(tk.END, line)
        history_box.tag_add(color, f"end-{len(line)}c", "end")
        history_box.tag_config(color, foreground=color)

    history_box.config(state=tk.DISABLED)

def export_history():
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return
    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Event", "Color"])
        writer.writerows(event_history)
    messagebox.showinfo("Export", f"History exported to {file_path}")

def clear_log():
    log_box.config(state=tk.NORMAL)
    log_box.delete(1.0, tk.END)
    log_box.config(state=tk.DISABLED)
    log_event("Logs cleared by user.", "orange")

# ================== SECURITY VARIABLES ==================
USERNAME = "Team1"
PASSWORD = "Smart@123"
login_attempts = 0
lock_time = 30
locked_until = 0
last_activity = time.time()

# ================== ENERGY VARIABLES ==================
current_usage = 0
status_var = None
status_color = None
overload_triggered = False
log_box = None
entry_password = None

# ================== RFID FUNCTIONS ==================
def find_rfid_port():
    ports = serial.tools.list_ports.comports()
    for port in ports:
        if "Arduino" in port.description or "USB-SERIAL" in port.description:
            return port.device
    return None

def read_rfid():
    global PASSWORD
    port = find_rfid_port()
    if not port:
        log_event("RFID reader not detected.", "red")
        return
    try:
        ser = serial.Serial(port, 9600, timeout=1)
        log_event(f"Connected to RFID on {port}", "blue")
    except serial.SerialException:
        log_event(f"Could not open {port}", "red")
        return

    while True:
        line = ser.readline().decode(errors='ignore').strip()
        if line and "RFID Tag UID:" in line:
            uid = line.split("RFID Tag UID:")[-1].strip().replace(" ", "")
            if uid:
                PASSWORD = uid
                log_event(f"RFID password updated: {PASSWORD}", "blue")
                try:
                    entry_password.delete(0, tk.END)
                    entry_password.insert(0, PASSWORD)
                except:
                    pass

# ================== SECURITY FUNCTIONS ==================
def login():
    global login_attempts, locked_until, last_activity
    username = entry_username.get()
    password = entry_password.get()

    if time.time() < locked_until:
        messagebox.showwarning("Locked", "Account is temporarily locked. Please wait.")
        return

    if username == USERNAME and password == PASSWORD:
        login_attempts = 0
        log_event("Login successful.", "green")
        last_activity = time.time()
        show_dashboard()
    else:
        login_attempts += 1
        log_event("Failed login attempt.", "red")
        messagebox.showerror("Error", "Invalid credentials.")
        if login_attempts >= 3:
            locked_until = time.time() + lock_time
            send_phone_alert("Smart Grid Security: Too many failed login attempts.")
            log_event("Account locked due to failed login attempts.", "red")
            messagebox.showwarning("Locked", f"Account locked for {lock_time} seconds.")

def auto_logout():
    global last_activity
    while True:
        if dashboard_frame.winfo_ismapped():
            if time.time() - last_activity > 60:  # 1 min inactivity
                dashboard_frame.pack_forget()
                login_frame.pack()
                log_event("Auto-logout due to inactivity.", "orange")
        time.sleep(5)

def show_dashboard():
    login_frame.pack_forget()
    dashboard_frame.pack(fill="both", expand=True)

def update_energy_usage():
    global current_usage, overload_triggered, last_activity
    while True:
        current_usage = random.randint(50, 500)
        usage_label.config(text=f"Current usage: {current_usage} W")
        usage_history.append(current_usage)
        update_graph()

        if current_usage > 300:
            if not overload_triggered:
                status_var.set(" Overload detected!")
                status_color.config(bg="red")
                send_phone_alert(f"Smart Grid ALERT: Overload! Usage = {current_usage}W")
                log_event(f"Overload detected: {current_usage}W", "red")
                overload_triggered = True
        else:
            if overload_triggered:
                status_var.set(" System back to normal.")
                status_color.config(bg="green")
                send_phone_alert(f"Smart Grid INFO: Usage back to normal at {current_usage}W.")
                log_event(f"System back to normal: {current_usage}W", "green")
                overload_triggered = False
            else:
                status_var.set("System running normally.")
                status_color.config(bg="green")
                log_event(f"Normal operation: {current_usage}W", "orange")

        last_activity = time.time()
        time.sleep(3)

def simulate_alert():
    log_event("Manual test alert triggered.", "blue")
    send_phone_alert("Smart Grid Test: This is a test alert.")

# ================== GRAPH ==================
def update_graph():
    ax.clear()
    ax.plot(usage_history[-20:], marker="o", color="cyan" if dark_mode else "blue")
    ax.set_title("Energy Usage (Last 20 samples)", color="white" if dark_mode else "black")
    ax.set_ylabel("Watts", color="white" if dark_mode else "black")
    ax.tick_params(colors="white" if dark_mode else "black")
    fig.patch.set_facecolor("#222" if dark_mode else "white")
    ax.set_facecolor("#333" if dark_mode else "white")
    canvas.draw()

# ================== DARK MODE ==================
dark_mode = False

def toggle_dark_mode():
    global dark_mode
    dark_mode = not dark_mode
    bg = "#222" if dark_mode else "#ffffff"
    fg = "white" if dark_mode else "black"

    # Update login frame
    login_frame.config(bg=bg)
    for widget in login_frame.winfo_children():
        if isinstance(widget, tk.Label):
            widget.config(bg=bg, fg=fg)
        elif isinstance(widget, tk.Entry):
            widget.config(bg="#444" if dark_mode else "white", fg=fg, insertbackground=fg)
        elif isinstance(widget, tk.Button):
            widget.config(bg="#555" if dark_mode else "#eee", fg=fg)

    # Update dashboard frame
    dashboard_frame.config(bg=bg)
    status_color.config(bg="green")
    usage_label.config(bg=bg, fg=fg)
    log_box.config(bg="#111" if dark_mode else "white", fg=fg)

    for widget in btn_frame.winfo_children():
        widget.config(bg="#555" if dark_mode else "#eee", fg=fg)

    update_graph()

# ================== GUI SETUP ==================
root = tk.Tk()
root.title("Smart Grid System (Enhanced)")
root.geometry("800x650")

# LOGIN FRAME
login_frame = tk.Frame(root, bg="#ffffff", bd=2)
tk.Label(login_frame, text="Username:", bg="#ffffff").grid(row=0, column=0, padx=5, pady=5)
entry_username = tk.Entry(login_frame)
entry_username.grid(row=0, column=1, padx=5, pady=5)

tk.Label(login_frame, text="Password:", bg="#ffffff").grid(row=1, column=0, padx=5, pady=5)
entry_password = tk.Entry(login_frame, show="*")
entry_password.grid(row=1, column=1, padx=5, pady=5)

tk.Button(login_frame, text="Login", command=login).grid(row=2, column=0, columnspan=2, pady=10)
login_frame.pack(pady=20)

# DASHBOARD FRAME
dashboard_frame = tk.Frame(root, bg="#ffffff", bd=2)
status_var = tk.StringVar(value="System running normally.")
status_color = tk.Label(dashboard_frame, width=20, height=2, bg="green")
status_color.pack(pady=5)
tk.Label(dashboard_frame, textvariable=status_var, font=("Arial", 12, "bold"), bg="#ffffff").pack(pady=5)
usage_label = tk.Label(dashboard_frame, text=f"Current usage: {current_usage} W", bg="#ffffff")
usage_label.pack(pady=5)

# LOG BOX
log_box = scrolledtext.ScrolledText(dashboard_frame, width=90, height=15, state=tk.DISABLED)
log_box.pack(pady=5)

# BUTTONS
btn_frame = tk.Frame(dashboard_frame, bg="#ffffff")
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="View Full History", command=show_history).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="Export History", command=export_history).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="Clear Log", command=clear_log).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Test Alert", command=simulate_alert).grid(row=0, column=3, padx=5)
tk.Button(btn_frame, text="Toggle Dark Mode", command=toggle_dark_mode).grid(row=0, column=4, padx=5)

# GRAPH
fig, ax = plt.subplots(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=dashboard_frame)
canvas.get_tk_widget().pack(pady=10)

# Start threads
threading.Thread(target=update_energy_usage, daemon=True).start()
threading.Thread(target=read_rfid, daemon=True).start()
threading.Thread(target=auto_logout, daemon=True).start()

root.mainloop()
