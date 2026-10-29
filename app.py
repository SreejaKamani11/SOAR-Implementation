
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timezone
from threading import Lock

app = Flask(__name__)
lock = Lock()

incidents = []
audit_log = []
next_id = 1

SEVERITY_LEVELS = {"low", "medium", "high", "critical"}

EVENTS = {
    "failed_login": "Multiple failed logins",
    "suspicious_process": "Suspicious process",
    "file_tampering": "File integrity violation",
    "network_anomaly": "Network anomaly"
}

DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
    <title>SOAR Security Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 25px;
               background: #f1f5f9; color: #172033; }
        .card { background: white; padding: 18px; margin: 15px 0;
                border-radius: 9px; box-shadow: 0 2px 7px #d7deea;
                overflow-x: auto; }
        h1 { color: #173b70; }
        input, select, button { padding: 10px; margin: 5px;
                                border-radius: 5px; }
        button { background: #1756a9; color: white; border: 0;
                 cursor: pointer; }
        table { width: 100%; border-collapse: collapse;
                background: white; }
        th, td { border: 1px solid #dce3ec; padding: 10px;
                 text-align: left; }
        th { background: #173b70; color: white; }
        .metrics { display: flex; flex-wrap: wrap; gap: 12px; }
        .metric { background: #e7efff; padding: 15px;
                  border-radius: 8px; min-width: 110px; }
        #message { font-weight: bold; }
    </style>
</head>
<body>
<h1>SOAR Security Dashboard</h1>
<p>Security Orchestration, Automation and Response</p>
<p>Educational prototype — all alerts are simulated.</p>

<div class="card">
    <h2>Create a Security Alert</h2>
    <form id="alertForm">
        <input name="source" placeholder="Source / test host" required
               maxlength="100">
        <select name="event_type">
            {% for key, label in events.items() %}
            <option value="{{ key }}">{{ label }}</option>
            {% endfor %}
        </select>
        <select name="severity">
            <option value="auto">Automatic severity</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
        </select>
        <button type="submit">Create Alert</button>
    </form>
    <p id="message"></p>
</div>

<div class="card">
    <h2>Incident Overview</h2>
    <div class="metrics">
        <div class="metric">Total<br><b>{{ total }}</b></div>
        <div class="metric">Open<br><b>{{ open_count }}</b></div>
        <div class="metric">Critical<br><b>{{ critical_count }}</b></div>
        <div class="metric">Resolved<br><b>{{ resolved_count }}</b></div>
    </div>
</div>

<div class="card">
    <h2>Incident Register</h2>
    <table>
        <tr>
            <th>ID</th><th>Time</th><th>Source</th><th>Event</th>
            <th>Severity</th><th>Status</th><th>Response</th><th>Action</th>
        </tr>
        {% for i in incidents %}
        <tr>
            <td>{{ i.id }}</td>
            <td>{{ i.time }}</td>
            <td>{{ i.source }}</td>
            <td>{{ events[i.event_type] }}</td>
            <td>{{ i.severity }}</td>
            <td>{{ i.status }}</td>
            <td>{{ i.response }}</td>
            <td>
                {% if i.status == 'open' %}
                <button onclick="resolveIncident({{ i.id }})">
                    Resolve
                </button>
                {% else %}
                —
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</div>

<div class="card">
    <h2>Recent Audit Events</h2>
    <ul>
    {% for event in audit %}
        <li>{{ event.time }} — {{ event.action }} —
            Incident {{ event.incident_id }}: {{ event.details }}</li>
    {% else %}
        <li>No audit events yet.</li>
    {% endfor %}
    </ul>
</div>

<script>
document.getElementById("alertForm").addEventListener("submit",
async function(e) {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    const response = await fetch("/api/alerts", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data)
    });
    const result = await response.json();
    document.getElementById("message").textContent =
        result.message || result.error;
    if (response.ok) location.reload();
});

async function resolveIncident(id) {
    const response = await fetch("/api/incidents/" + id + "/resolve",
                                 {method: "POST"});
    const result = await response.json();
    if (response.ok) location.reload();
    else alert(result.error || "Could not resolve incident");
}
</script>
</body>
</html>
"""


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def record_audit(action, incident_id, details):
    audit_log.append({
        "time": timestamp(),
        "action": action,
        "incident_id": incident_id,
        "details": details
    })


def classify_severity(event_type):
    rules = {
        "failed_login": "high",
        "suspicious_process": "high",
        "file_tampering": "medium",
        "network_anomaly": "medium"
    }
    return rules.get(event_type, "low")


def recommend_response(severity, event_type):
    # Recommendations only: no real device or account is changed.
    if severity == "critical":
        return "Escalate immediately for analyst review"
    if severity == "high":
        return "Notify analyst and investigate"
    if event_type == "file_tampering":
        return "Verify file integrity and investigate"
    return "Record event and monitor"


@app.route("/")
def dashboard():
    with lock:
        data = [dict(i) for i in incidents]
        audit = [dict(e) for e in reversed(audit_log[-10:])]

    return render_template_string(
        DASHBOARD,
        incidents=data,
        audit=audit,
        events=EVENTS,
        total=len(data),
        open_count=sum(i["status"] == "open" for i in data),
        critical_count=sum(i["severity"] == "critical" for i in data),
        resolved_count=sum(i["status"] == "resolved" for i in data)
    )


@app.route("/api/alerts", methods=["POST"])
def create_alert():
    global next_id
    data = request.get_json(silent=True) or {}

    source = str(data.get("source", "")).strip()[:100]
    event_type = str(data.get("event_type", "")).strip()
    requested = str(data.get("severity", "auto")).lower()

    if not source:
        return jsonify(error="Source is required"), 400
    if event_type not in EVENTS:
        return jsonify(error="Invalid event type"), 400
    if requested != "auto" and requested not in SEVERITY_LEVELS:
        return jsonify(error="Invalid severity"), 400

    severity = (classify_severity(event_type)
                if requested == "auto" else requested)

    with lock:
        incident_id = next_id
        next_id += 1

        incident = {
            "id": incident_id,
            "time": timestamp(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "status": "open",
            "response": recommend_response(severity, event_type)
        }
        incidents.append(incident)
        record_audit("ALERT_CREATED", incident_id,
                     "Severity: " + severity)

    return jsonify(message="Alert created successfully",
                   incident=incident), 201


@app.route("/api/incidents/<int:incident_id>/resolve", methods=["POST"])
def resolve_incident(incident_id):
    with lock:
        for incident in incidents:
            if incident["id"] == incident_id:
                if incident["status"] == "resolved":
                    return jsonify(message="Already resolved"), 200

                incident["status"] = "resolved"
                record_audit("INCIDENT_RESOLVED", incident_id,
                             "Marked resolved by operator")
                return jsonify(message="Incident resolved"), 200

    return jsonify(error="Incident not found"), 404


@app.route("/api/audit", methods=["GET"])
def get_audit():
    with lock:
        return jsonify(audit_log)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(status="ok", project="SOAR prototype")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
