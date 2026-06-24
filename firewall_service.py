"""
XSS Detection Firewall Service for Kali Linux
==============================================
Flask-based API that integrates with Nginx for real-time XSS detection.

Deployment:
    1. Copy this project to /opt/xss-firewall on Kali
    2. Install dependencies: pip install flask gunicorn
    3. Run: gunicorn --workers 4 --bind 127.0.0.1:5000 firewall_service:app
"""

from flask import Flask, request, jsonify
import numpy as np
import re
import os
import sys
import logging

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
from datetime import datetime
from functools import lru_cache

# Add project path (script is at deployment/server_client/firewall_service.py)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEPLOY_DIR = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DEPLOY_DIR)
sys.path.insert(0, PROJECT_ROOT)

# Configure logging
LOG_DIR = '/var/log/xss-firewall'
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except PermissionError:
    # Fallback to local logs if not running as root
    LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
    os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'detections.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('XSS-Firewall')

app = Flask(__name__)

# ============================================================================
# XSS Detection Patterns
# ============================================================================

XSS_PATTERNS = [
    # Script tags - Critical
    (r'<script[^>]*>', 'script_tag', 10),
    (r'</script>', 'script_close', 10),
    (r'<script[^>]*>[^<]*</script>', 'script_block', 15),

    # JavaScript protocol - Critical
    (r'javascript\s*:', 'js_protocol', 10),
    (r'vbscript\s*:', 'vbscript', 10),
    (r'livescript\s*:', 'livescript', 10),

    # Event handlers - High
    (r'on(error|load|click|mouseover|mouseout|mousedown|mouseup|mousemove)\s*=', 'mouse_event', 8),
    (r'on(keydown|keyup|keypress|focus|blur|change|submit|reset|select)\s*=', 'form_event', 8),
    (r'on(abort|beforeunload|hashchange|message|offline|online|popstate)\s*=', 'window_event', 8),
    (r'on(resize|scroll|storage|unload|wheel|copy|cut|paste)\s*=', 'misc_event', 7),
    (r'on(start|toggle|animationend|animationstart|transitionend|drag|drop)\s*=', 'extra_event', 8),

    # Inline JS injection patterns (no HTML tags)
    (r"['\"][\s]*[-;][\s]*alert\s*\(", 'inline_js_alert', 8),
    (r'["\'][\s]*;[\s]*alert\s*\(', 'context_break_alert', 8),

    # Common JS attack functions
    (r'alert\s*\(', 'alert_func', 7),
    (r'confirm\s*\(', 'confirm_func', 6),
    (r'prompt\s*\(', 'prompt_func', 6),

    # Dangerous functions - Critical
    (r'eval\s*\(', 'eval_func', 10),
    (r'Function\s*\(', 'function_constructor', 9),
    (r'setTimeout\s*\([^)]*["\']', 'settimeout_string', 8),
    (r'setInterval\s*\([^)]*["\']', 'setinterval_string', 8),

    # DOM manipulation - High
    (r'document\.(cookie|domain|write|writeln)', 'doc_access', 8),
    (r'document\.(location|URL|referrer)', 'doc_location', 7),
    (r'document\.(getElementById|getElementsBy|querySelector)', 'doc_query', 5),
    (r'window\.(location|open|eval|execScript)', 'win_access', 8),
    (r'(innerHTML|outerHTML|insertAdjacentHTML)\s*=', 'html_injection', 8),
    (r'(innerText|textContent)\s*=', 'text_injection', 4),

    # Dangerous HTML tags - High to Critical
    (r'<iframe[^>]*>', 'iframe', 10),
    (r'<frame[^>]*>', 'frame', 9),
    (r'<object[^>]*>', 'object_tag', 9),
    (r'<embed[^>]*>', 'embed_tag', 9),
    (r'<applet[^>]*>', 'applet', 9),
    (r'<meta[^>]*http-equiv', 'meta_refresh', 9),
    (r'<base[^>]*href', 'base_href', 10),
    (r'<link[^>]*rel\s*=\s*["\']?import', 'link_import', 8),

    # SVG/MathML attacks
    (r'<svg[^>]*on\w+\s*=', 'svg_event', 9),
    (r'<svg[^>]*>', 'svg_tag', 4),
    (r'<math[^>]*>', 'math_tag', 4),
    (r'<animate[^>]*>', 'animate_tag', 5),

    # Image attacks
    (r'<img[^>]*on\w+\s*=', 'img_event', 9),
    (r'<img[^>]*src\s*=\s*["\']?javascript:', 'img_js_src', 10),
    (r'<input[^>]*on\w+\s*=', 'input_event', 8),
    (r'<body[^>]*on\w+\s*=', 'body_event', 9),

    # Style-based attacks
    (r'expression\s*\(', 'css_expression', 8),
    (r'url\s*\(\s*["\']?javascript:', 'css_js_url', 9),
    (r'behavior\s*:', 'css_behavior', 7),
    (r'-moz-binding\s*:', 'moz_binding', 7),

    # Encoding attacks - Low to Medium
    (r'&#x[0-9a-fA-F]{2,4};', 'hex_entity', 4),
    (r'&#\d{2,5};', 'decimal_entity', 4),
    (r'%3C|%3E|%22|%27|%3D|%2F', 'url_encoding', 3),
    (r'\\u00[0-9a-fA-F]{2}', 'unicode_escape', 4),
    (r'\\x[0-9a-fA-F]{2}', 'hex_escape', 4),

    # String manipulation
    (r'String\.fromCharCode', 'fromcharcode', 7),
    (r'atob\s*\(', 'base64_decode', 6),
    (r'btoa\s*\(', 'base64_encode', 3),
    (r'unescape\s*\(', 'unescape_func', 5),
    (r'decodeURI(Component)?\s*\(', 'decode_uri', 4),

    # Data URIs
    (r'data\s*:\s*text/html', 'data_html', 8),
    (r'data\s*:\s*application/javascript', 'data_js', 9),
    (r'data\s*:\s*[^;,]*;base64', 'data_base64', 6),

    # Template injection
    (r'\{\{[^}]+\}\}', 'template_expr', 5),
    (r'\$\{[^}]+\}', 'template_literal', 5),
    (r'<%[^%]+%>', 'server_template', 6),
]

# ============================================================================
# Model Loading
# ============================================================================

MODEL = None
FEATURE_EXTRACTOR = None
SELECTED_FEATURE_INDICES = None
MODEL_LOADED = False

# MAFS ensemble (10-agent feature-selection decomposition) + self-supervised adapter
MAFS = None
ADAPTER = None
try:
    from multi_agent_loader import MAFSEnsemble
    from online_adapter import OnlineAdapter
    ADAPTER = OnlineAdapter(num_agents=10)
except Exception as _e:
    logger.warning(f"MAFS/Adapter import failed: {_e}")

def load_model():
    """Load the trained ML model, feature extractor, and selected feature indices."""
    global MODEL, FEATURE_EXTRACTOR, SELECTED_FEATURE_INDICES, MODEL_LOADED

    if MODEL_LOADED:
        return MODEL is not None

    model_paths = [
        # Local model (same folder)
        os.path.join(SCRIPT_DIR, 'models', 'xss_classifier.joblib'),
        # Project root paths
        os.path.join(PROJECT_ROOT, 'models', 'xss_classifier.joblib'),
        os.path.join(PROJECT_ROOT, 'models', 'xss_classifier.pkl'),
        os.path.join(PROJECT_ROOT, 'results', 'model.pkl'),
        os.path.join(PROJECT_ROOT, 'results', 'best_model.pkl'),
        # Standard /opt deployment paths
        '/opt/xss-firewall/models/xss_classifier.joblib',
        '/opt/xss-firewall/models/xss_classifier.pkl',
        '/opt/xss-firewall/results/best_model.pkl',
    ]

    # Try to load model (joblib preferred for security)
    for path in model_paths:
        if os.path.exists(path):
            try:
                if JOBLIB_AVAILABLE:
                    data = joblib.load(path)
                else:
                    import pickle
                    with open(path, 'rb') as f:
                        data = pickle.load(f)

                if isinstance(data, dict):
                    MODEL = data.get('classifier') or data.get('model')
                    FEATURE_EXTRACTOR = data.get('feature_extractor')
                    SELECTED_FEATURE_INDICES = data.get('selected_feature_indices')
                    clf_name = data.get('classifier_name', 'unknown')
                    n_selected = data.get('selected_features_count', '?')
                    logger.info(f"Model loaded from {path} ({clf_name}, {n_selected} features)")

                    # Build the MAFS ensemble view over the same joblib payload
                    global MAFS
                    try:
                        MAFS = MAFSEnsemble(data)
                        logger.info(f"MAFS ensemble ready: {MAFS.NUM_AGENTS} agents x {MAFS.features_per_agent} features")
                    except Exception as me:
                        logger.warning(f"MAFS ensemble disabled: {me}")
                else:
                    MODEL = data
                    logger.info(f"Model loaded from {path}")
                break
            except Exception as e:
                logger.error(f"Failed to load model from {path}: {e}")

    # Try to load feature extractor separately if not in model package
    if FEATURE_EXTRACTOR is None:
        try:
            from data.feature_extractor import XSSFeatureExtractor
            FEATURE_EXTRACTOR = XSSFeatureExtractor()
            sample_texts = [
                "Hello world",
                "<script>alert(1)</script>",
                "<img onerror=alert(1)>",
                "javascript:void(0)"
            ]
            FEATURE_EXTRACTOR.extract_all_features(sample_texts, fit=True)
            logger.info("Feature extractor initialized separately")
        except Exception as e:
            logger.warning(f"Feature extractor not available: {e}")

    MODEL_LOADED = True

    if MODEL is not None:
        logger.info("ML model ready for hybrid detection")
    else:
        logger.warning("Using pattern-based detection only (no ML model)")

    return MODEL is not None

# ============================================================================
# Detection Functions
# ============================================================================

def detect_xss_patterns(text: str) -> dict:
    """Fast pattern-based XSS detection."""
    if not text:
        return {'is_xss': False, 'score': 0, 'patterns': [], 'raw_score': 0}

    found_patterns = []
    total_score = 0

    for pattern, name, weight in XSS_PATTERNS:
        try:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            if matches:
                count = len(matches)
                found_patterns.append({
                    'name': name,
                    'count': count,
                    'weight': weight,
                    'severity': 'critical' if weight >= 9 else 'high' if weight >= 7 else 'medium' if weight >= 5 else 'low'
                })
                total_score += count * weight
        except re.error:
            continue

    # Normalize score (0-1), cap at 1.0
    normalized_score = min(1.0, total_score / 50.0)

    # Determine if XSS based on score and pattern severity
    has_critical = any(p['severity'] == 'critical' for p in found_patterns)
    has_high = any(p['severity'] == 'high' for p in found_patterns)

    is_xss = (normalized_score >= 0.3 or
              has_critical or
              (has_high and len(found_patterns) >= 2) or
              total_score >= 15)

    return {
        'is_xss': is_xss,
        'score': normalized_score,
        'patterns': found_patterns,
        'raw_score': total_score
    }

def detect_xss_ml(text: str) -> dict:
    """ML-based XSS detection using GNN-DQN-MAFS trained model."""
    if MODEL is None or FEATURE_EXTRACTOR is None:
        return None

    try:
        # Extract all 430 features
        features, _, _ = FEATURE_EXTRACTOR.extract_all_features([text], fit=False)
        features = features[0].reshape(1, -1)

        # Apply GNN-DQN feature selection (222/430 features)
        if SELECTED_FEATURE_INDICES is not None:
            valid_indices = [i for i in SELECTED_FEATURE_INDICES if i < features.shape[1]]
            features = features[:, valid_indices]

        # Predict
        if hasattr(MODEL, 'predict_proba'):
            proba = MODEL.predict_proba(features)[0]
            score = float(proba[1]) if len(proba) > 1 else float(proba[0])
        else:
            pred = MODEL.predict(features)[0]
            score = float(pred)

        return {
            'is_xss': score >= 0.5,
            'score': score,
            'method': 'ml'
        }
    except Exception as e:
        logger.error(f"ML detection error: {e}")
        return None

def detect_xss(text: str) -> dict:
    """Combined XSS detection using both patterns and ML."""
    # Pattern-based detection (always run - fast)
    pattern_result = detect_xss_patterns(text)

    # ML-based detection (if available)
    ml_result = detect_xss_ml(text)

    # Combine results
    if ml_result:
        # Weighted combination: 60% ML, 40% patterns
        combined_score = 0.6 * ml_result['score'] + 0.4 * pattern_result['score']

        # Smart detection: require pattern confirmation for borderline ML scores
        # This prevents false positives when ML alone flags safe text
        has_pattern_evidence = len(pattern_result['patterns']) > 0
        pattern_is_xss = pattern_result['is_xss']

        if pattern_is_xss:
            # Pattern detection confirms → trust it
            is_xss = True
        elif combined_score >= 0.75:
            # Very high combined score → trust ML even without patterns
            is_xss = True
        elif combined_score >= 0.5 and has_pattern_evidence:
            # Medium score but has some pattern evidence → block
            is_xss = True
        else:
            # ML-only detection with low/no pattern support → likely false positive
            is_xss = False

        method = 'hybrid'
    else:
        combined_score = pattern_result['score']
        is_xss = pattern_result['is_xss']
        method = 'pattern'

    # Determine risk level
    if combined_score >= 0.8:
        risk_level = 'critical'
    elif combined_score >= 0.6:
        risk_level = 'high'
    elif combined_score >= 0.4:
        risk_level = 'medium'
    else:
        risk_level = 'low'

    return {
        'is_xss': is_xss,
        'score': combined_score,
        'risk_level': risk_level,
        'method': method,
        'patterns': pattern_result['patterns'],
        'pattern_score': pattern_result['score'],
        'ml_score': ml_result['score'] if ml_result else None,
        'timestamp': datetime.now().isoformat()
    }

# ============================================================================
# API Endpoints
# ============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': MODEL is not None,
        'feature_extractor_loaded': FEATURE_EXTRACTOR is not None,
        'detection_method': 'hybrid' if MODEL else 'pattern',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/detect', methods=['POST'])
def detect():
    """
    Main detection endpoint for Nginx auth_request integration.
    Returns 200 if safe, 403 if XSS detected.
    """
    data = request.get_json() or {}

    # Collect all text sources to analyze
    texts_to_check = []

    # Check URI
    if 'uri' in data and data['uri']:
        texts_to_check.append(('uri', data['uri']))

    # Check query parameters
    if 'args' in data and data['args']:
        texts_to_check.append(('args', data['args']))

    # Check request body
    if 'body' in data and data['body']:
        texts_to_check.append(('body', data['body']))

    # Check specific headers
    if 'headers' in data and isinstance(data['headers'], dict):
        for header in ['referer', 'user-agent', 'cookie', 'x-forwarded-for']:
            if header in data['headers'] and data['headers'][header]:
                texts_to_check.append((f'header_{header}', data['headers'][header]))

    # Analyze all collected texts
    detections = []
    is_blocked = False
    max_score = 0

    for source, text in texts_to_check:
        if text:
            result = detect_xss(str(text))
            if result['is_xss']:
                is_blocked = True
                detections.append({
                    'source': source,
                    'score': result['score'],
                    'risk_level': result['risk_level'],
                    'patterns': [p['name'] for p in result['patterns'][:5]]
                })
            max_score = max(max_score, result['score'])

    # Log detection
    client_ip = data.get('client_ip', request.remote_addr or 'unknown')

    if is_blocked:
        logger.warning(
            f"XSS BLOCKED | IP: {client_ip} | "
            f"Score: {max_score:.2f} | "
            f"Sources: {[d['source'] for d in detections]} | "
            f"URI: {data.get('uri', 'N/A')[:100]}"
        )
    else:
        logger.debug(f"ALLOWED | IP: {client_ip} | Score: {max_score:.2f}")

    # Response
    response = {
        'blocked': is_blocked,
        'score': max_score,
        'detections': detections,
        'client_ip': client_ip,
        'timestamp': datetime.now().isoformat()
    }

    status_code = 403 if is_blocked else 200
    return jsonify(response), status_code

@app.route('/check', methods=['GET', 'POST'])
def check_simple():
    """Simple check endpoint for testing."""
    if request.method == 'POST':
        data = request.get_json() or {}
        text = data.get('text', '')
    else:
        text = request.args.get('text', '')

    if not text:
        return jsonify({'error': 'No text provided', 'usage': 'GET /check?text=<input> or POST with {"text": "<input>"}'}), 400

    result = detect_xss(text)
    return jsonify(result)

@app.route('/batch', methods=['POST'])
def batch_check():
    """Batch check multiple texts."""
    data = request.get_json() or {}
    texts = data.get('texts', [])

    if not texts:
        return jsonify({'error': 'No texts provided'}), 400

    results = []
    for i, text in enumerate(texts[:100]):  # Limit to 100
        result = detect_xss(str(text))
        result['index'] = i
        result['text_preview'] = text[:50] + '...' if len(text) > 50 else text
        results.append(result)

    blocked_count = sum(1 for r in results if r['is_xss'])

    return jsonify({
        'total': len(results),
        'blocked': blocked_count,
        'safe': len(results) - blocked_count,
        'results': results
    })

@app.route('/stats', methods=['GET'])
def stats():
    """Get firewall statistics from log file."""
    stats = {
        'model_loaded': MODEL is not None,
        'detection_method': 'hybrid' if MODEL else 'pattern',
        'total_patterns': len(XSS_PATTERNS),
        'blocked_today': 0,
        'total_blocked': 0
    }

    log_file = os.path.join(LOG_DIR, 'detections.log')
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                stats['total_blocked'] = sum(1 for l in lines if 'XSS BLOCKED' in l)

                today = datetime.now().strftime('%Y-%m-%d')
                stats['blocked_today'] = sum(1 for l in lines if 'XSS BLOCKED' in l and today in l)
        except:
            pass

    return jsonify(stats)

@app.route('/patterns', methods=['GET'])
def list_patterns():
    """List all detection patterns."""
    patterns_info = []
    for pattern, name, weight in XSS_PATTERNS:
        patterns_info.append({
            'name': name,
            'weight': weight,
            'severity': 'critical' if weight >= 9 else 'high' if weight >= 7 else 'medium' if weight >= 5 else 'low'
        })

    return jsonify({
        'total': len(patterns_info),
        'patterns': patterns_info
    })

@app.route('/reload', methods=['POST'])
def reload_model():
    """Reload the ML model."""
    global MODEL_LOADED
    MODEL_LOADED = False
    success = load_model()
    return jsonify({
        'success': success,
        'model_loaded': MODEL is not None
    })


# ============================================================================
# MAFS Multi-Agent + Online Adaptation Endpoints
# ============================================================================

@app.route('/api/agents-verdict', methods=['POST'])
def api_agents_verdict():
    """Run MAFS pipeline + adaptive observer for one input string."""
    if MAFS is None:
        return jsonify({'error': 'MAFS ensemble not loaded'}), 503

    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    if not text:
        return jsonify({'error': 'Field "text" is required'}), 400

    try:
        prediction = MAFS.predict(text)
    except Exception as e:
        logger.error(f"MAFS predict error: {e}")
        return jsonify({'error': f'MAFS predict failed: {e}'}), 500

    adapter_event = None
    if ADAPTER is not None:
        try:
            adapter_event = ADAPTER.observe(text, prediction)
        except Exception as e:
            logger.error(f"Adapter observe error: {e}")

    pattern_result = detect_xss_patterns(text)

    return jsonify({
        'text':            text[:300],
        'mafs':            prediction,
        'adapter_event':   adapter_event,
        'regex_baseline':  {
            'is_xss':  pattern_result['is_xss'],
            'score':   pattern_result['score'],
            'matches': [p['name'] for p in pattern_result['patterns'][:8]],
        },
    })


@app.route('/api/adapter-state', methods=['GET'])
def api_adapter_state():
    """Return current state of the online self-supervised adapter."""
    if ADAPTER is None:
        return jsonify({'error': 'Adapter not active'}), 503
    return jsonify(ADAPTER.state())


@app.route('/api/mafs-info', methods=['GET'])
def api_mafs_info():
    """Static metadata about the MAFS ensemble."""
    if MAFS is None:
        return jsonify({'error': 'MAFS not loaded'}), 503

    agent_summary = []
    for i, slice_idx in enumerate(MAFS.agent_slices):
        kept = [idx for idx in slice_idx if idx in MAFS._selected_set]
        agent_summary.append({
            'agent_id':       i,
            'slice_start':    slice_idx[0],
            'slice_end':      slice_idx[-1],
            'slice_size':     len(slice_idx),
            'kept_count':     len(kept),
            'drop_count':     len(slice_idx) - len(kept),
            'keep_rate':      round(len(kept) / max(len(slice_idx), 1), 4),
        })

    return jsonify({
        'num_agents':         MAFS.NUM_AGENTS,
        'features_per_agent': MAFS.features_per_agent,
        'features_total':     MAFS.total_features,
        'selected_total':     len(MAFS.selected_indices),
        'agents':             agent_summary,
    })


@app.route('/api/diversity-benchmark', methods=['GET'])
def api_diversity_benchmark():
    """Run a fixed benchmark of attack categories through MAFS, return per-agent activation heatmap."""
    if MAFS is None:
        return jsonify({'error': 'MAFS not loaded'}), 503

    benchmark = [
        ('Benign',        'hello world how are you today'),
        ('Script',        '<script>alert(1)</script>'),
        ('Event handler', '<img src=x onerror=alert(1)>'),
        ('JS URL',        '<a href="javascript:alert(1)">click</a>'),
        ('SVG',           '<svg onload=alert(1)>'),
        ('Encoded',       '%3Cscript%3Ealert(1)%3C/script%3E'),
        ('Polyglot',      "jaVaScRipT:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1))//%0D%0A%0D%0A//"),
        ('DOM-based',     "<input onfocus=eval('alert(1)') autofocus>"),
    ]

    rows = []
    for label, payload in benchmark:
        try:
            r = MAFS.predict(payload)
            rows.append({
                'label':            label,
                'payload':          payload,
                'score':            r['score'],
                'is_xss':           r['is_xss'],
                'active_votes':     r['active_votes'],
                'agent_active':     [a['active_count'] for a in r['agents']],
                'agent_score':      [a['activation_score'] for a in r['agents']],
            })
        except Exception as e:
            logger.error(f"Benchmark item failed ({label}): {e}")

    return jsonify({'benchmark': rows})

# ============================================================================
# Error Handlers
# ============================================================================

# ============================================================================
# Protected Web Application (for XSSer comparison testing)
# ============================================================================

SEARCH_HTML = """<!DOCTYPE html>
<html><head><title>Search - Protected by GNN-DQN-MAFS</title></head>
<body>
<h1>Web Application Search</h1>
<form method="GET" action="/search">
  <input type="text" name="q" value="{query}" size="60">
  <input type="submit" value="Search">
</form>
<div id="results">
  <h3>Search results for: {query}</h3>
  <p>No results found for your query.</p>
</div>
<footer><small>Protected by GNN-DQN-MAFS Firewall</small></footer>
</body></html>"""

@app.route('/search', methods=['GET', 'POST'])
def search_protected():
    """Protected search page - checks XSS before reflecting input."""
    query = request.args.get('q', '') or request.form.get('q', '')
    if not query:
        safe_html = SEARCH_HTML.replace('{query}', '')
        return safe_html, 200

    # Run XSS detection on the query
    result = detect_xss(query)

    if result['is_xss']:
        logger.warning(f"XSS BLOCKED in /search | query: {query[:100]} | score: {result['score']:.3f}")
        return f"""<!DOCTYPE html>
<html><head><title>403 Blocked</title></head>
<body>
<h1>403 - Request Blocked</h1>
<p>XSS attack detected and blocked by GNN-DQN-MAFS Firewall.</p>
<p>Risk Level: {result['risk_level']} | Score: {result['score']:.3f}</p>
<p>Detection Method: {result['method']}</p>
</body></html>""", 403

    # Safe - reflect the query (escaped for display)
    import html as html_module
    safe_query = html_module.escape(query)
    safe_html = SEARCH_HTML.replace('{query}', safe_query)
    return safe_html, 200

@app.route('/', methods=['GET'])
def index():
    """Main page."""
    return """<!DOCTYPE html>
<html><head><title>GNN-DQN-MAFS Protected Server</title></head>
<body>
<h1>GNN-DQN-MAFS XSS Firewall</h1>
<p>Status: Running</p>
<ul>
  <li><a href="/search?q=test">Search Page (Protected)</a></li>
  <li><a href="/health">Health Check API</a></li>
  <li><a href="/check?text=hello">Detection API</a></li>
</ul>
</body></html>""", 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'error': 'Endpoint not found',
        'available_endpoints': [
            'GET / - Main page',
            'GET /search?q=<query> - Search (protected)',
            'GET /health - Health check',
            'POST /detect - Main detection (for Nginx)',
            'GET/POST /check?text=<input> - Simple check',
            'POST /batch - Batch check',
            'GET /stats - Statistics',
            'GET /patterns - List patterns',
            'POST /reload - Reload model'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# Initialization
# ============================================================================

# Load model on startup
load_model()

if __name__ == '__main__':
    print("=" * 60)
    print("XSS Detection Firewall Service")
    print("=" * 60)
    print(f"Model loaded: {MODEL is not None}")
    print(f"Feature extractor: {FEATURE_EXTRACTOR is not None}")
    print(f"Detection patterns: {len(XSS_PATTERNS)}")
    print(f"Log directory: {LOG_DIR}")
    print("=" * 60)

    app.run(host='0.0.0.0', port=5000, debug=False)
