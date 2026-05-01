import streamlit as st
import pandas as pd
import sqlite3
import plotly.graph_objects as go
import time

st.set_page_config(page_title="FlowShield UI", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
    <style>
    .stApp { background-color: #0E1117; }
    h1, h2, h3 { color: #00ff00; font-family: monospace; }
    </style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=2)
def get_latest_data():
    try:
        conn = sqlite3.connect("flowshield_logs.db")
        df = pd.read_sql_query("SELECT timestamp, src, dst, type, speed FROM alerts ORDER BY timestamp DESC LIMIT 200",
                               conn)
        conn.close()

        if not df.empty:
            df['Time'] = pd.to_datetime(df['timestamp'], unit='s')
            df['Time_Str'] = df['Time'].dt.strftime('%H:%M:%S')

            colors = []
            for t in df['type']:
                t_up = str(t).upper()
                if "FLOOD" in t_up:
                    colors.append('#ff3333')  # Red
                elif "SCAN" in t_up:
                    colors.append('#ffaa00')  # Orange
                elif "AI" in t_up or "PATTERN" in t_up:
                    colors.append('#00ffff')  # Cyan
                else:
                    colors.append('#00ff00')  # Green
            df['Color'] = colors

        return df
    except Exception as e:
        # print(f"DB Error: {e}")
        return pd.DataFrame()


def main():
    st.title("FlowShield")
    st.markdown("Live network telemetry and threat mitigation status.")
    st.markdown("---")

    df = get_latest_data()

    if df.empty:
        st.info("Waiting for data. Ensure flowshield_live.py is capturing traffic.")
        return

    col1, col2, col3, col4 = st.columns(4)

    total_logs = len(df)
    attacks = df[~df['type'].str.contains("Normal", case=False, na=False)]
    threat_count = len(attacks)

    current_speed = int(df.iloc[0]['speed'])
    sys_status = "UNDER ATTACK" if threat_count > 0 and current_speed > 30 else "SECURE"

    col1.metric("Status", sys_status)
    col2.metric("Events (Last 200)", total_logs)
    col3.metric("Threats Detected", threat_count)
    col4.metric("Current PPS", f"{current_speed}")

    st.write("<br>", unsafe_allow_html=True)

    st.subheader("Traffic Intensity")

    graph_df = df.head(60).sort_values('Time')

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=graph_df['Time'],
        y=graph_df['speed'],
        mode='lines',
        line=dict(color='#00ff00', width=2, dash='solid'),
        name='Bandwidth',
        hoverinfo='skip'
    ))

    fig.add_trace(go.Scatter(
        x=graph_df['Time'],
        y=graph_df['speed'],
        mode='markers',
        marker=dict(
            color=graph_df['Color'],
            size=12,
            line=dict(color='white', width=1)
        ),
        text=graph_df['type'],
        hovertemplate="<b>Time:</b> %{x}<br><b>Speed:</b> %{y} pps<br><b>Event:</b> %{text}<extra></extra>",
        name='Events'
    ))

    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color="white",
        xaxis_title="Time",
        yaxis_title="Packets / Sec",
        showlegend=False,
        margin=dict(l=0, r=0, t=10, b=10)
    )

    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(gridcolor='#333333', gridwidth=1)

    st.plotly_chart(fig, width="stretch")

    st.subheader("Alert Log")

    table_df = df[['Time_Str', 'type', 'src', 'speed']].copy()
    table_df.columns = ["Time", "Type", "Source IP", "Speed (PPS)"]

    def color_rows(row):
        t_up = str(row['Type']).upper()
        if "FLOOD" in t_up:
            color = '#ff3333'
        elif "SCAN" in t_up:
            color = '#ffaa00'
        elif "AI" in t_up or "PATTERN" in t_up:
            color = '#00ffff'
        else:
            color = '#00ff00'
        return [f'color: {color}'] * len(row)

    styled_df = table_df.style.apply(color_rows, axis=1)
    st.dataframe(styled_df, width="stretch", height=300)

    time.sleep(2)
    st.rerun()


if __name__ == "__main__":
    main()