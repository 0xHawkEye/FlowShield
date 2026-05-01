import matplotlib.pyplot as plt
import matplotlib.animation as animation
import sqlite3
import time
from datetime import datetime

# Config
DB_FILE = "flowshield_logs.db"
REFRESH_RATE = 1000
ATTACK_THRESHOLD = 50

plt.style.use('dark_background')
plt.rcParams['font.family'] = 'monospace'

fig = plt.figure(figsize=(12, 8))
fig.canvas.manager.set_window_title('FlowShield Enterprise Monitor - CSOC')
fig.patch.set_facecolor('#0a0a0a')

# grid layout
ax1 = plt.subplot2grid((4, 1), (0, 0), rowspan=3)  # Graph
ax2 = plt.subplot2grid((4, 1), (3, 0), rowspan=1)  # Table


def fetch_data():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        current_time = time.time()
        c.execute("SELECT timestamp, speed, type FROM alerts WHERE timestamp > ?", (current_time - 60,))
        graph_data = c.fetchall()

        c.execute("SELECT timestamp, type, src, speed FROM alerts ORDER BY id DESC LIMIT 5")
        table_data = c.fetchall()
        conn.close()
        return graph_data, table_data
    except:
        return [], []


def animate(i):
    graph_data, table_data = fetch_data()

    ax1.clear()
    ax1.set_facecolor('#0a0a0a')
    current_time = time.time()

    is_under_attack = False

    if graph_data:
        x_vals = [row[0] - current_time for row in graph_data]
        y_vals = [row[1] for row in graph_data]
        types = [row[2] for row in graph_data]

        if max(y_vals) > ATTACK_THRESHOLD:
            is_under_attack = True

        line_color = '#ff3333' if is_under_attack else '#00ff00'
        fill_alpha = 0.3 if is_under_attack else 0.1

        ax1.plot(x_vals, y_vals, color=line_color, linewidth=2, label='Traffic Intensity')
        ax1.fill_between(x_vals, y_vals, color=line_color, alpha=fill_alpha)

        colors = []
        for t in types:
            t_upper = t.upper()
            if "FLOOD" in t_upper:
                colors.append('#ff3333')  # Red for Floods
            elif "SCAN" in t_upper:
                colors.append('#ffaa00')  # Orange for Scans
            elif "PATTERN MATCH" in t_upper or "AI" in t_upper:
                colors.append('#00ffff')  # Cyan for AI Slowloris
            else:
                colors.append('#00ff00')  # Green for Ignored/Normal Traffic

        ax1.scatter(x_vals, y_vals, c=colors, s=120, edgecolors='white', zorder=10)

    if is_under_attack:
        ax1.text(0.02, 0.90, "⚠️ SYSTEM UNDER ATTACK", transform=ax1.transAxes, color='#ff3333', fontsize=18,
                 fontweight='bold')
    else:
        ax1.text(0.02, 0.90, "✅ SYSTEM NORMAL", transform=ax1.transAxes, color='#00ff00', fontsize=14,
                 fontweight='bold')

    ax1.set_title("🛡️ FLOWSHIELD LIVE THREAT TELEMETRY", fontsize=16, color='white', fontweight='bold', pad=15)
    ax1.set_ylabel("PACKETS / SEC", color='#888888', fontweight='bold')
    ax1.set_xlim(-60, 2)
    max_y = max([y for y in [row[1] for row in graph_data]] + [50]) * 1.2 if graph_data else 50
    ax1.set_ylim(0, max_y)
    ax1.grid(True, color='#222222', linestyle=':')
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.spines['bottom'].set_color('#444444')
    ax1.spines['left'].set_color('#444444')

    ax2.clear()
    ax2.axis('off')

    if table_data:
        cell_text = []
        for row in table_data:
            t_str = datetime.fromtimestamp(row[0]).strftime('%H:%M:%S')
            alert_type = row[1]
            src_ip = row[2]
            speed = f"{int(row[3])} pps"
            cell_text.append([t_str, alert_type, src_ip, speed])

        the_table = ax2.table(cellText=cell_text,
                              colLabels=["TIMESTAMP", "THREAT CLASSIFICATION", "SOURCE IP", "INTENSITY"], loc='center',
                              cellLoc='left')
        the_table.auto_set_font_size(False)
        the_table.set_fontsize(11)
        the_table.scale(1, 1.8)

        for (row, col), cell in the_table.get_celld().items():
            cell.set_edgecolor('#222222')

            if row == 0:
                cell.set_text_props(weight='bold', color='#00ffff')
                cell.set_facecolor('#111111')
            else:
                t_upper = cell_text[row - 1][1].upper()
                if "FLOOD" in t_upper:
                    text_color = '#ff3333'
                elif "SCAN" in t_upper:
                    text_color = '#ffaa00'
                elif "PATTERN MATCH" in t_upper or "AI" in t_upper:
                    text_color = '#00ffff'
                else:
                    text_color = '#00ff00'

                cell.set_text_props(color=text_color)
                cell.set_facecolor('#0a0a0a')


print("[*] 📡 INITIALIZING CSOC DASHBOARD...")
ani = animation.FuncAnimation(fig, animate, interval=REFRESH_RATE, cache_frame_data=False)
plt.tight_layout()
plt.show()