from flask import Flask, render_template, request
import pandas as pd
from datetime import datetime, timedelta

app = Flask(__name__)

@app.route("/", methods=["GET"])
def dashboard():
    try:
        df = pd.read_csv("traffic_log.csv")
    except FileNotFoundError:
        return render_template("dashboard.html", total_packets=0,
                               top_protocols={}, top_ips={},
                               current_protocol="", current_ip="", current_minutes="")

    # Ensure Timestamp is datetime
    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])
    else:
        return render_template("dashboard.html", total_packets=0,
                               top_protocols={}, top_ips={},
                               current_protocol="", current_ip="", current_minutes="")

    # Get filters
    protocol = request.args.get("protocol", "").strip().upper()
    ip = request.args.get("ip", "").strip()
    minutes = request.args.get("minutes", "").strip()

    if protocol:
        df = df[df["Protocol"].str.upper() == protocol]
    if ip:
        df = df[df["Source IP"] == ip]
    if minutes.isdigit():
        time_threshold = datetime.now() - timedelta(minutes=int(minutes))
        df = df[df["Timestamp"] >= time_threshold]

    top_protocols = df["Protocol"].value_counts().to_dict()
    top_ips = df["Source IP"].value_counts().head(5).to_dict()

    return render_template("dashboard.html",
                           total_packets=len(df),
                           top_protocols=top_protocols,
                           top_ips=top_ips,
                           current_protocol=protocol,
                           current_ip=ip,
                           current_minutes=minutes)

if __name__ == "__main__":
    app.run(debug=True)
