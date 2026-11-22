from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import base64
import hmac
import hashlib
import struct
import time
import threading
import webbrowser


def get_totp(secret, offset=0):
    key = base64.b32decode(secret.upper())
    counter = int(time.time() // 30) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[o:o+4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.csrf_token = ""

    def request(self, method, path, data=None, include_csrf=True):
        url = self.base_url + path
        headers = {}
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if include_csrf and self.csrf_token and method in ("POST", "PUT", "DELETE"):
            headers["X-CSRF-Token"] = self.csrf_token
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=5) as resp:
                raw = resp.read().decode("utf-8")
                parsed = json.loads(raw) if raw.startswith("{") or raw.startswith("[") else raw
                if isinstance(parsed, dict) and "csrf_token" in parsed:
                    self.csrf_token = parsed["csrf_token"]
                return resp.status, parsed
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw
            return e.code, parsed


def run_suite_data(base_url):
    c = HttpClient(base_url)
    c.request("GET", "/session")
    res_map = {}

    # 1. MFA Verification Check (Fake OTP)
    st, res = c.request("POST", "/login", {"username": "omar", "password": "UserSecret2026!", "otp": "999999"})
    res_map["mfa"] = {
        "blocked": st in (401, 403, 429),
        "text": f"HTTP {st} ({'Blocked' if st != 200 else 'Bypassed!'})",
        "raw": res
    }
    if st == 200:
        c.request("POST", "/logout")
        c.request("GET", "/session")

    # 2. TOTP Anti-Replay Check
    valid_otp = get_totp("JBSWY3DPEHPK3PXP")
    st1, _ = c.request("POST", "/login", {"username": "omar", "password": "UserSecret2026!", "otp": valid_otp})
    c.request("POST", "/logout")
    c.request("GET", "/session")
    st2, res2 = c.request("POST", "/login", {"username": "omar", "password": "UserSecret2026!", "otp": valid_otp})
    res_map["replay"] = {
        "blocked": st2 in (401, 403, 429),
        "text": f"1st: {st1} | Replay: {st2}",
        "raw": {"first_status": st1, "replay_status": st2, "response": res2}
    }

    # 3. Parameterized SQL Query Check
    sqli = urllib.parse.quote("' UNION SELECT 1,username,password_hash,email,store_credit,role FROM users --")
    st, res = c.request("GET", f"/products?search={sqli}")
    leaked = len(res) if isinstance(res, list) else 0
    res_map["sqli"] = {
        "blocked": leaked == 0,
        "text": f"HTTP {st} | Rows Returned: {leaked}",
        "raw": res
    }

    # Register & confirm fresh user for authenticated checks (4, 5, 6)
    c.request("GET", "/session")
    temp_user = f"tester_{int(time.time() * 1000) % 1000000}"
    _, reg = c.request("POST", "/register", {"username": temp_user, "email": f"{temp_user}@sut.edu.eg", "password": "UserSecret2026!"})
    if isinstance(reg, dict) and "confirmation_code" in reg:
        c.request("POST", "/confirm", {"username": temp_user, "confirmation_code": reg["confirmation_code"]})
        c.request("POST", "/login", {"username": temp_user, "password": "UserSecret2026!", "otp": get_totp(reg["totp_secret"])})
    else:
        c.request("POST", "/login", {"username": "omar", "password": "UserSecret2026!", "otp": get_totp("JBSWY3DPEHPK3PXP")})

    # 4. CSRF Token Enforcement Check
    st, res = c.request("POST", "/cart/add", {"product_id": 1, "quantity": 1}, include_csrf=False)
    res_map["csrf"] = {
        "blocked": st == 403,
        "text": f"HTTP {st} ({'Rejected' if st == 403 else 'Accepted!'})",
        "raw": res
    }

    # 5. Server-Side Price Integrity Check
    c.request("POST", "/cart/add", {"product_id": 1, "quantity": 1}, include_csrf=True)
    st, res = c.request("POST", "/checkout", {"total": 1.00}, include_csrf=True)
    res_map["price"] = {
        "blocked": st == 400,
        "text": f"HTTP {st} ({'Rejected' if st == 400 else 'Accepted $1!'})",
        "raw": res
    }

    # 6. Admin Endpoint RBAC Check
    st, res = c.request("GET", "/admin/users")
    res_map["rbac"] = {
        "blocked": st in (401, 403),
        "text": f"HTTP {st} ({'Forbidden' if st in (401, 403) else 'Dumped Users!'})",
        "raw": res
    }

    # 7. Rate-Limit Lockout Check
    c.request("POST", "/logout")
    c.request("GET", "/session")
    bf_codes = []
    last_res = {}
    for i in range(6):
        st, last_res = c.request("POST", "/login", {"username": "omar", "password": f"WrongPass{i}", "otp": "123456"})
        bf_codes.append(st)
    locked = 429 in bf_codes
    res_map["bruteforce"] = {
        "blocked": locked,
        "text": f"Tries: {bf_codes}",
        "raw": {"attempt_statuses": bf_codes, "final_response": last_res}
    }

    return res_map


def execute_comparison():
    try:
        naive_data = run_suite_data("http://127.0.0.1:5001")
    except Exception as e:
        return {"error": f"Cannot connect to Naive App (:5001). Make sure naive_app.py is running! ({e})"}

    try:
        hard_data = run_suite_data("http://127.0.0.1:5000")
    except Exception as e:
        return {"error": f"Cannot connect to Hardened App (:5000). Make sure app.py is running! ({e})"}

    tests = [
        ("01", "mfa", "MFA Verification (Fake OTP 999999)", "POST /login", "Authentication"),
        ("02", "replay", "TOTP Anti-Replay (Same 30s Window)", "POST /login", "Authentication"),
        ("03", "sqli", "Parameterized SQL Query (UNION Check)", "GET /products", "Injection"),
        ("04", "csrf", "CSRF Token Enforcement (Missing Header)", "POST /cart/add", "Session & CSRF"),
        ("05", "price", "Server-Side Price Integrity ($1.00 Check)", "POST /checkout", "Business Logic"),
        ("06", "rbac", "Admin Endpoint RBAC Authorization", "GET /admin/users", "Access Control"),
        ("07", "bruteforce", "Rate-Limit Lockout (6 Failed Attempts)", "POST /login", "Rate Limiting"),
    ]

    rows = []
    for idx, key, name, endpoint, cat in tests:
        rows.append({
            "id": idx,
            "name": name,
            "endpoint": endpoint,
            "category": cat,
            "naive": naive_data[key],
            "hardened": hard_data[key]
        })

    return {"rows": rows, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SecureShop | Comparative Security Results (CET431)</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1120; color: #e2e8f0; padding: 24px; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { background: #111827; border: 1px solid #1f2937; border-radius: 14px; padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }
    .badge { display: inline-block; background: #083344; color: #22d3ee; border: 1px solid #155e75; font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 6px; letter-spacing: 0.5px; }
    h1 { font-size: 22px; color: #f8fafc; margin-top: 8px; }
    .sub { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .btn { background: #06b6d4; color: #082f49; border: none; padding: 11px 20px; border-radius: 10px; font-weight: 700; font-size: 13px; cursor: pointer; }
    .btn:hover { background: #22d3ee; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 20px; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 16px 20px; }
    .card-title { font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .card-val { font-size: 28px; font-weight: 800; margin-top: 6px; }
    .c-white { color: #f8fafc; } .c-red { color: #fb7185; } .c-green { color: #34d399; } .c-cyan { color: #22d3ee; }
    .error-banner { background: #4c0519; border: 1px solid #be123c; color: #fecdd3; padding: 14px 18px; border-radius: 10px; margin-bottom: 18px; font-size: 14px; display: none; }
    .panel { background: #111827; border: 1px solid #1f2937; border-radius: 14px; overflow: hidden; margin-bottom: 20px; }
    .panel-head { padding: 14px 20px; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center; }
    .panel-head h2 { font-size: 15px; color: #f8fafc; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #0f172a; color: #94a3b8; text-align: left; padding: 12px 16px; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid #1f2937; }
    td { padding: 13px 16px; border-bottom: 1px solid #1f2937; vertical-align: middle; }
    tr:hover { background: #1e293b; cursor: pointer; }
    tr.active-row { background: #172554; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .pill { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }
    .pill-vuln { background: #4c0519; color: #fda4af; border: 1px solid #9f1239; }
    .pill-safe { background: #022c22; color: #6ee7b7; border: 1px solid #065f46; }
    .inspector { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 800px) { .inspector { grid-template-columns: 1fr; } }
    pre { background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 14px; font-size: 12px; max-height: 260px; overflow: auto; margin-top: 8px; white-space: pre-wrap; word-break: break-word; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <span class="badge">CET431 SOFTWARE SECURITY</span>
        <span id="ts" class="sub" style="margin-left:10px;">Running initial checks...</span>
        <h1>SecureShop Comparative Verification Dashboard</h1>
        <p class="sub">Side-by-side results: <span class="mono c-red">Naive Baseline (:5001)</span> vs <span class="mono c-green">Hardened SecureShop (:5000)</span></p>
      </div>
      <button id="runBtn" class="btn" onclick="runComparison()">Re-Run Live Comparison</button>
    </div>

    <div id="errBox" class="error-banner"></div>

    <div class="kpis">
      <div class="card"><div class="card-title">Total Security Checks</div><div id="kTotal" class="card-val c-white">7</div></div>
      <div class="card"><div class="card-title">Naive (:5001) Vulnerable</div><div id="kNaive" class="card-val c-red">—</div></div>
      <div class="card"><div class="card-title">Hardened (:5000) Protected</div><div id="kHard" class="card-val c-green">—</div></div>
      <div class="card"><div class="card-title">Defense Pass Rate</div><div id="kRate" class="card-val c-cyan">—</div></div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>Comparative Security Test Results</h2>
        <span class="sub">Click any row to inspect raw JSON responses below</span>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Test Scenario & Endpoint</th>
              <th>Naive App (:5001)</th>
              <th>Hardened App (:5000)</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="tbody">
            <tr><td colspan="5" style="text-align:center; padding:30px; color:#94a3b8;">Loading live results...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="inspector">
      <div class="card">
        <div class="card-title c-red">Naive Baseline (:5001) Raw JSON Response</div>
        <pre id="rawNaive" class="mono c-red">Select a row above...</pre>
      </div>
      <div class="card">
        <div class="card-title c-green">Hardened SecureShop (:5000) Raw JSON Response</div>
        <pre id="rawHard" class="mono c-green">Select a row above...</pre>
      </div>
    </div>
  </div>

  <script>
    let rowsData = [];

    function esc(v) {
      return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    async function runComparison() {
      const btn = document.getElementById('runBtn');
      const err = document.getElementById('errBox');
      btn.disabled = true;
      btn.textContent = 'Running Checks...';
      err.style.display = 'none';

      try {
        const res = await fetch('/api/run');
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        rowsData = data.rows;
        document.getElementById('ts').textContent = 'Verified at: ' + data.timestamp;
        renderRows();
      } catch (e) {
        err.textContent = e.message;
        err.style.display = 'block';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Re-Run Live Comparison';
      }
    }

    function renderRows() {
      const tbody = document.getElementById('tbody');
      tbody.innerHTML = '';
      let vulnCount = 0;
      let safeCount = 0;

      rowsData.forEach((r, i) => {
        if (!r.naive.blocked) vulnCount++;
        if (r.hardened.blocked) safeCount++;

        const tr = document.createElement('tr');
        tr.onclick = () => selectRow(i, tr);
        tr.innerHTML = `
          <td class="mono">${esc(r.id)}</td>
          <td>
            <div style="font-weight:700; color:#f8fafc;">${esc(r.name)}</div>
            <div class="mono" style="color:#38bdf8; margin-top:3px;">${esc(r.endpoint)} · <span style="color:#94a3b8;">${esc(r.category)}</span></div>
          </td>
          <td class="mono c-red">${esc(r.naive.text)}</td>
          <td class="mono c-green">${esc(r.hardened.text)}</td>
          <td>${r.hardened.blocked ? '<span class="pill pill-safe">DEFENDED</span>' : '<span class="pill pill-vuln">EXPOSED</span>'}</td>
        `;
        tbody.appendChild(tr);
      });

      document.getElementById('kTotal').textContent = rowsData.length;
      document.getElementById('kNaive').textContent = vulnCount + ' / ' + rowsData.length;
      document.getElementById('kHard').textContent = safeCount + ' / ' + rowsData.length;
      document.getElementById('kRate').textContent = Math.round((safeCount / rowsData.length) * 100) + '%';

      if (tbody.firstChild) selectRow(0, tbody.firstChild);
    }

    function selectRow(idx, trEl) {
      document.querySelectorAll('#tbody tr').forEach(el => el.classList.remove('active-row'));
      trEl.classList.add('active-row');
      document.getElementById('rawNaive').textContent = JSON.stringify(rowsData[idx].naive.raw, null, 2);
      document.getElementById('rawHard').textContent = JSON.stringify(rowsData[idx].hardened.raw, null, 2);
    }

    window.onload = runComparison;
  </script>
</body>
</html>
"""


class ReusableThreadingServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/run":
            payload = json.dumps(execute_comparison()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
        else:
            page = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    url = "http://127.0.0.1:5050"
    print(f"Dashboard running at: {url}")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    server = ReusableThreadingServer(("127.0.0.1", 5050), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()