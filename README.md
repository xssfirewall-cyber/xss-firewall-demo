# Cybersecurity Framework for Detection and Prevention of Cross-Site Scripting Attacks Using Hybrid Deep Learning Techniques

> **MSc. Thesis Demonstration**
> **Student:** Ali Nafea Yousif
> **Supervised By:** Prof. Dr. Ziyad Tariq Mustafa Al-Ta'i

A live, browser-based demonstration of a hybrid XSS detection and prevention firewall that combines pattern-based heuristics, a trained machine-learning classifier, and a **10-agent GNN-DQN Multi-Agent Feature Selection (MAFS)** ensemble — wrapped in a self-supervised continual-learning loop.

**Live demo:** https://xssfirewall.pythonanywhere.com

---

## 1. What the project does

The system inspects arbitrary text or HTML input and decides whether it constitutes an XSS attack. It does this on three layers:

| Layer | Detector | Role |
| --- | --- | --- |
| 1 | 62 hand-crafted **regex patterns** | Fast first-line filter |
| 2 | **Gradient-Boosting classifier** trained on 226 features | Catches obfuscated / mutated payloads regex misses |
| 3 | **10 GNN-DQN agents** (MAFS) | Per-agent decomposition of feature selection, used as a transparent, multi-vote explanation surface and as the basis for the adaptive layer |

A self-supervised **OnlineAdapter** sits on top: it converts every prediction into a pseudo-supervised signal (via consensus / entropy of the agent votes), accumulates concept-drift evidence, and issues micro-update events without any labelled feedback from a human.

---

## 2. The 10-agent MAFS architecture

The 430 raw input features extracted from the request are partitioned into ten contiguous slices of 43 features each. Each slice is the responsibility of one GNN-DQN agent that learned, during training, which of its features survive into the final selection. The union of all ten agents' kept features is the 226-dimensional selected set fed to the final classifier.

```
text ─▶ XSSFeatureExtractor ─▶ 430 features ─┬─ Agent 0 → kept ⊂ [0..42]
                                              ├─ Agent 1 → kept ⊂ [43..85]
                                              ├─ Agent 2 → kept ⊂ [86..128]
                                              ├─ Agent 3 → kept ⊂ [129..171]
                                              ├─ Agent 4 → kept ⊂ [172..214]
                                              ├─ Agent 5 → kept ⊂ [215..257]
                                              ├─ Agent 6 → kept ⊂ [258..300]
                                              ├─ Agent 7 → kept ⊂ [301..343]
                                              ├─ Agent 8 → kept ⊂ [344..386]
                                              └─ Agent 9 → kept ⊂ [387..429]
                                                       │
                                                       ▼  union (226 features)
                                              Gradient-Boosting → BENIGN / MALICIOUS
```

Persisted artefacts:

- `models/xss_classifier.joblib` — trained classifier + feature extractor + selected indices (the MAFS output baked in)
- `models/gnn_dqn_agents/gcn_late_agent_{0..9}.keras` — the ten GNN-DQN networks (kept as research artefacts)

---

## 3. Self-supervised continual learning

The runtime adapter (`online_adapter.py`) maintains:

- a sliding **replay buffer** of recent events
- a **binary entropy** measure over the per-input vote ratio
- a **drift counter** that accumulates high-entropy / mid-score events
- a per-agent **disagreement score** and **exploration rate (ε)**

Decision rule per request:

| Vote ratio + score | Flag | Action |
| --- | --- | --- |
| Low entropy + score < 0.30 | `consensus_benign` | Pseudo-labelled 0 |
| Low entropy + score > 0.70 | `consensus_xss` | Pseudo-labelled 1 |
| High entropy / mid score | `uncertain` | Drift counter ++ |

Once the drift counter crosses a threshold, a **micro-update event** is emitted: the three most disagreeing agents have their ε decayed and their disagreement score halved. The dashboard surfaces all of this live.

---

## 4. Dashboard — Multi-Agent System Analysis

Four interactive tabs:

1. **MAFS Panel** — submit any payload; ten agent cards render each agent's `kept / active / activation_score`. A summary banner shows classifier score, ensemble votes, total selected features.
2. **Mutation Lab** — preset attack variants (script, event handler, JS URL, SVG, URL-encoded, polyglot, DOM-based). Each variant is sent through MAFS and compared side-by-side with the pure-regex baseline.
3. **Diversity Heatmap** — runs a fixed benchmark of 8 attack categories through MAFS and renders a 10 × 8 heatmap of per-agent active-feature counts, visualising agent specialisation.
4. **Adaptive Learning** — live dashboard polling the adapter every 2 s: disagreement-entropy gauge, pseudo-label vs. uncertain counters, drift counter, per-agent ε bars, recent events stream, micro-update log.

Recent Detections, headline counters, MAFS Panel and Adaptive Learning all **auto-refresh every 5 s**, so an attack arriving from anywhere (Check Input, `/victim/*`, batch demo) is visible across the dashboard with no manual reload.

---

## 5. Victim site — `/victim/*`

A second Flask Blueprint (`victim_site.py`) simulates a vulnerable web application — Search, Comments, Login — protected by the firewall. Every submission is checked by `detect_xss()` and, if classified as XSS, the page is replaced by a red **🚨 XSS ATTACK BLOCKED!** screen. Each victim-site detection is also forwarded into the main dashboard history (`hybrid (victim)` method tag) so reviewers can demonstrate live attack interception from a second browser tab.

Routes:

- `/victim/` — landing page
- `/victim/search` — reflected-context demo
- `/victim/comments` — stored-context demo
- `/victim/login` — auth-form demo

---

## 6. Project layout

```
xss-firewall-demo/
├── app.py                       Main Flask app, dashboard endpoints, blueprint registration
├── firewall_service.py          Pattern + ML detector, MAFS loader, model bootstrap
├── multi_agent_loader.py        MAFSEnsemble class (10-agent decomposition over joblib)
├── online_adapter.py            Self-supervised continual-learning adapter
├── victim_site.py               Vulnerable demo target Blueprint (/victim/*)
├── templates/
│   └── index.html               Dashboard + 4 tabs + auto-refresh polling JS
├── data/
│   ├── feature_extractor.py     430-feature extractor (bundled for standalone deploy)
│   └── __init__.py
├── config/
│   ├── settings.py              Project configuration (bundled for standalone deploy)
│   └── __init__.py
├── models/
│   ├── xss_classifier.joblib    Trained classifier + extractor + selected indices
│   └── gnn_dqn_agents/
│       ├── gcn_late_agent_0..9.keras   Ten GNN-DQN feature-selector networks
│       └── README.md
├── requirements.txt             flask, joblib, scikit-learn, numpy, pandas
├── render.yaml                  Render.com deployment manifest
└── README.md
```

---

## 7. Running locally

```bash
git clone https://github.com/xssfirewall-cyber/xss-firewall-demo.git
cd xss-firewall-demo
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
python app.py
```

Open <http://localhost:5000>.

### Required versions for the trained model

The persisted `xss_classifier.joblib` was created with:

- Python 3.10+
- scikit-learn 1.7+ (recommended) or 1.8
- numpy 2.x
- pandas 2.2+

Older scikit-learn / numpy combinations will fail to unpickle the classifier.

---

## 8. Deploying to PythonAnywhere (free tier tested)

```bash
# In a Bash console on PythonAnywhere:
git clone https://github.com/xssfirewall-cyber/xss-firewall-demo.git
mkvirtualenv --python=python3.10 xss-env
pip install scikit-learn==1.7.2 pandas>=2.2 "numpy>=2.0,<3"
pip install -r xss-firewall-demo/requirements.txt
```

Web tab → Manual configuration → Python 3.10. Set the WSGI file to:

```python
import sys
path = '/home/<username>/xss-firewall-demo'
if path not in sys.path:
    sys.path.insert(0, path)
from app import app as application
```

Source code: `/home/<username>/xss-firewall-demo`
Virtualenv: `/home/<username>/.virtualenvs/xss-env`
Reload.

---

## 9. API surface

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Dashboard UI |
| `/api/check` | POST `{text}` | Hybrid detection on a single input |
| `/api/batch-demo` | POST | Run 10 canned payloads |
| `/api/history` | GET | Recent detection log (last 50) |
| `/api/stats` | GET | Counters + uptime |
| `/api/agents-verdict` | POST `{text}` | Full MAFS pipeline — per-agent breakdown + regex baseline + adapter event |
| `/api/adapter-state` | GET | OnlineAdapter live state |
| `/api/mafs-info` | GET | Static MAFS metadata (agent slices, kept counts) |
| `/api/diversity-benchmark` | GET | Run 8 attack categories through MAFS for the heatmap |
| `/victim/` | GET | Vulnerable site landing page |
| `/victim/search`, `/victim/comments`, `/victim/login` | GET / POST | Protected form endpoints |

---

## 10. Acknowledgements

This demonstration accompanies the M.Sc. thesis

> *Cybersecurity framework for Detection and Prevention of Cross-Site Scripting Attacks Using Hybrid Deep Learning Techniques*

by **Ali Nafea Yousif**, supervised by **Prof. Dr. Ziyad Tariq Mustafa Al-Ta'i**.
