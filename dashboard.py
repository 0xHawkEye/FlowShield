import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sqlite3
import time
from datetime import datetime

# Config
DB_FILE = "flowshield_logs.db"
REFRESH_RATE = 1000

plt.style.use('dark_background')
plt.rcParams['font.family'] = 'monospace'

fig = plt.figure(figsize=(12, 8))
fig.canvas.manager.set_window_title('FlowShield CSOC Monitor')
fig.patch.set_facecolor('#0a0a0a')

ax1 = plt.subplot2grid((4, 1), (0, 0), rowspan=3)
ax2 = plt.subplot2grid((4, 1), (3, 0), rowspan=1)


def fetch_data():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        curr = time.time()
        c.execute("SELECT timestamp, speed, type FROM alerts WHERE timestamp > ?", (curr - 60,))
        g_data = c.fetchall()
        c.execute("SELECT timestamp, type, src, speed FROM alerts ORDER BY id DESC LIMIT 5")
        t_data = c.fetchall()
        conn.close()
        return g_data, t_data
    except:
        return [], []


def animate(i):
    g_data, t_data = fetch_data()
    ax1.clear()
    ax1.set_facecolor('#0a0a0a')
    curr = time.time()

    is_critical, is_suspicious = False, False
    if g_data:
        x = [r[0] - curr for r in g_data]
        y = [r[1] for r in g_data]
        types = [r[2] for r in g_data]

        for t in types:
            if "FLOOD" in t.upper() or "SCAN" in t.upper():
                is_critical = True
            elif "AI" in t.upper() or "PATTERN" in t.upper():
                is_suspicious = True

        color = '#ff3333' if is_critical else ('#00ffff' if is_suspicious else '#00ff00')
        ax1.plot(x, y, color=color, linewidth=2)
        ax1.fill_between(x, y, color=color, alpha=0.2)

        dot_colors = ['#ff3333' if "FLOOD" in t.upper() else ('#00ffff' if "AI" in t.upper() else '#00ff00') for t in
                      types]
        ax1.scatter(x, y, c=dot_colors, s=80, edgecolors='white', zorder=10)

    status = "[!!!] CRITICAL" if is_critical else ("[?] SUSPICIOUS" if is_suspicious else "[+] SECURE")
    status_color = '#ff3333' if is_critical else ('#00ffff' if is_suspicious else '#00ff00')
    ax1.text(0.02, 0.92, status, transform=ax1.transAxes, color=status_color, fontsize=16, fontweight='bold')

    ax1.set_title("FLOWSHIELD THREAT TELEMETRY", fontsize=14, color='white', pad=15)
    ax1.set_xlim(-60, 2)
    ax1.set_ylim(0, max([r[1] for r in g_data] + [100]) * 1.2 if g_data else 100)
    ax1.grid(True, color='#222222', linestyle=':')

    ax2.clear()
    ax2.axis('off')
    if t_data:
        cell_text = [[datetime.fromtimestamp(r[0]).strftime('%H:%M:%S'), r[1], r[2], f"{int(r[3])} pps"] for r in
                     t_data]
        tab = ax2.table(cellText=cell_text, colLabels=["TIME", "THREAT", "SOURCE IP", "SPEED"], loc='center',
                        cellLoc='left')
        tab.auto_set_font_size(False);
        tab.set_fontsize(10);
        tab.scale(1, 1.5)
        for (r, c), cell in tab.get_celld().items():
            cell.set_edgecolor('#222222')
            cell.set_facecolor('#0a0a0a' if r > 0 else '#1a1a1a')
            if r > 0:
                cell_type = cell_text[r - 1][1].upper()
                cell.set_text_props(
                    color=('#ff3333' if "FLOOD" in cell_type else ('#00ffff' if "AI" in cell_type else '#00ff00')))


print("[*] 📡 Launching CSOC Interface...")
ani = animation.FuncAnimation(fig, animate, interval=REFRESH_RATE, cache_frame_data=False)
plt.tight_layout()
plt.show()