from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Cyber Sidecar – Live Alerts</title>
    <style>
      body { font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif; padding: 16px; background:#050816; color:#f5f5f5;}
      table { border-collapse: collapse; width: 100%; margin-top: 12px;}
      th, td { border-bottom: 1px solid #333; padding: 6px 8px; font-size: 13px;}
      th { text-align: left; background:#111827;}
      tr:nth-child(even) { background:#020617; }
      .pill { padding: 2px 8px; border-radius: 999px; font-size: 11px; }
      .pill.low { background:#0f766e22; color:#6ee7b7;}
      .pill.medium { background:#f9731622; color:#fdba74;}
      .pill.high { background:#b91c1c22; color:#fecaca;}
      button { background:#1d4ed8; border:none; color:white; padding:4px 10px; border-radius:999px; cursor:pointer; font-size:11px;}
      button:hover { background:#2563eb;}
    </style>
  </head>
  <body>
    <h1>Live Alerts</h1>
    <p>Unacknowledged high-risk exports from the last 5 minutes.</p>
    <table>
      <thead>
        <tr>
          <th>Time (UTC)</th>
          <th>User</th>
          <th>Session</th>
          <th>IP</th>
          <th>Resource</th>
          <th>Score</th>
          <th>Level</th>
          <th>Reasons</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
    <script>
      async function fetchAlerts() {
        const res = await fetch('/alerts/live?minutes=5&min_score=40');
        const data = await res.json();
        const tbody = document.getElementById('rows');
        tbody.innerHTML = '';
        for (const a of data) {
          const tr = document.createElement('tr');
          const reasons = (a.reasons || []).join('; ');
          tr.innerHTML = `
            <td>${a.finding_created_at_utc}</td>
            <td>${a.user_id || ''}</td>
            <td>${a.session_id || ''}</td>
            <td>${a.resource && a.resource.startsWith('http') ? '' : ''}</td>
            <td>${a.resource || ''}</td>
            <td>${a.risk_score}</td>
            <td><span class="pill ${a.risk_level}">${a.risk_level}</span></td>
            <td>${reasons}</td>
            <td><button data-id="${a.id}">Ack</button></td>
          `;
          tbody.appendChild(tr);
        }
        for (const btn of document.querySelectorAll('button[data-id]')) {
          btn.onclick = async () => {
            const id = btn.getAttribute('data-id');
            await fetch(`/alerts/${id}/ack`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-User-Id': 'josh' },
              body: JSON.stringify({ note: 'Ack via UI' })
            });
            fetchAlerts();
          };
        }
      }
      fetchAlerts();
      setInterval(fetchAlerts, 5000);
    </script>
  </body>
</html>
"""

@router.get("/ui/alerts", response_class=HTMLResponse)
async def alerts_ui():
    return HTML
