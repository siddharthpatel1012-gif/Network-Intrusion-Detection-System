from flask import Flask, Response, jsonify
import json, time, os, csv, io
from ids_engine import IDS

BASE = os.path.dirname(os.path.abspath(__file__))
app  = Flask(__name__, template_folder=os.path.join(BASE, "templates"))
ids  = IDS()
ids.start()

@app.route("/")
def index():
    with open(os.path.join(BASE, "templates", "dashboard.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.route("/api/state")
def state():
    return jsonify(ids.get_state())

@app.route("/api/stream")
def stream():
    def gen():
        while True:
            try:
                data = ids.get_state()
                yield f"data: {json.dumps(data)}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            time.sleep(1)
    return Response(gen(), mimetype="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "Access-Control-Allow-Origin": "*"
                    })

@app.route("/api/export/csv")
def export_csv():
    alerts = ids.get_state().get("alerts", [])
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id","timestamp","severity","attack_type",
        "src_ip","dst_ip","dst_port","protocol","anomaly_score","description"
    ])
    writer.writeheader()
    writer.writerows(alerts)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ids_alerts.csv"})

if __name__ == "__main__":
    print("=" * 60)
    print("  Network IDS Dashboard  (Enhanced)")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 60)
    app.run(debug=False, threaded=True, port=5000)