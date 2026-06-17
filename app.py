import streamlit as st
import joblib
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from feature_extraction import extract_features
from virustotal_scan import scan_url
from risk_engine import calculate_risk

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI · URL Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base & fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Background ── */
.stApp {
    background: #0a0c10;
    color: #c9d1d9;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #21262d;
}
section[data-testid="stSidebar"] .stMarkdown h1,
section[data-testid="stSidebar"] .stMarkdown h2,
section[data-testid="stSidebar"] .stMarkdown h3,
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] .stMarkdown li {
    color: #c9d1d9;
}

/* ── Headings ── */
h1 { color: #e6edf3 !important; letter-spacing: -0.5px; }
h2, h3 { color: #c9d1d9 !important; }

/* ── Input ── */
.stTextInput > div > div > input {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
    color: #e6edf3 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.9rem !important;
    padding: 0.6rem 1rem !important;
}
.stTextInput > div > div > input:focus {
    border-color: #388bfd !important;
    box-shadow: 0 0 0 3px rgba(56, 139, 253, 0.15) !important;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    padding: 0.55rem 2rem !important;
    transition: all 0.2s ease !important;
    letter-spacing: 0.3px !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 20px rgba(31, 111, 235, 0.4) !important;
}

/* ── Cards ── */
.card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
}
.card-header {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: #8b949e;
    margin-bottom: 0.4rem;
}
.card-value {
    font-size: 2rem;
    font-weight: 700;
    color: #e6edf3;
    font-family: 'JetBrains Mono', monospace;
}
.card-sub {
    font-size: 0.8rem;
    color: #8b949e;
    margin-top: 0.2rem;
}

/* ── Metric override ── */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 1rem 1.25rem;
}
[data-testid="stMetricLabel"] { color: #8b949e !important; font-size: 0.78rem !important; }
[data-testid="stMetricValue"] { color: #e6edf3 !important; font-family: 'JetBrains Mono', monospace !important; }
[data-testid="stMetricDelta"] svg { display: none; }

/* ── Progress bars ── */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #1f6feb, #388bfd) !important;
    border-radius: 4px !important;
}
.stProgress > div > div {
    background: #21262d !important;
    border-radius: 4px !important;
    height: 8px !important;
}

/* ── Risk cards ── */
.risk-low {
    background: rgba(35, 134, 54, 0.12);
    border: 1px solid #238636;
    border-radius: 10px;
    padding: 1.1rem 1.5rem;
    color: #3fb950;
}
.risk-medium {
    background: rgba(187, 128, 9, 0.12);
    border: 1px solid #bb8009;
    border-radius: 10px;
    padding: 1.1rem 1.5rem;
    color: #e3b341;
}
.risk-high {
    background: rgba(219, 106, 28, 0.12);
    border: 1px solid #db6a1c;
    border-radius: 10px;
    padding: 1.1rem 1.5rem;
    color: #f0883e;
}
.risk-critical {
    background: rgba(218, 54, 51, 0.12);
    border: 1px solid #da3633;
    border-radius: 10px;
    padding: 1.1rem 1.5rem;
    color: #f85149;
}
.risk-title {
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-bottom: 0.3rem;
    opacity: 0.8;
}
.risk-value {
    font-size: 1.6rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}
.risk-desc {
    font-size: 0.8rem;
    margin-top: 0.25rem;
    opacity: 0.75;
}

/* ── Prediction card ── */
.pred-safe {
    background: rgba(35, 134, 54, 0.1);
    border: 2px solid #238636;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    text-align: center;
}
.pred-phishing {
    background: rgba(218, 54, 51, 0.1);
    border: 2px solid #da3633;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    text-align: center;
}
.pred-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
.pred-label {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 0.5px;
}
.pred-safe .pred-label { color: #3fb950; }
.pred-phishing .pred-label { color: #f85149; }
.pred-note { font-size: 0.82rem; color: #8b949e; margin-top: 0.4rem; }

/* ── VT stat boxes ── */
.vt-box {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    text-align: center;
}
.vt-box-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-bottom: 0.3rem; }
.vt-box-value { font-size: 1.8rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.vt-malicious .vt-box-value { color: #f85149; }
.vt-suspicious .vt-box-value { color: #f0883e; }
.vt-harmless .vt-box-value { color: #3fb950; }

/* ── Section divider ── */
.section-label {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: #388bfd;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.section-label::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #21262d;
}

/* ── Expander ── */
details {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 10px !important;
}
details summary {
    color: #8b949e !important;
    font-size: 0.88rem !important;
    font-weight: 500 !important;
    padding: 0.75rem 1rem !important;
}

/* ── Code blocks ── */
code {
    background: #0d1117 !important;
    color: #79c0ff !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.82rem !important;
    border-radius: 4px !important;
    padding: 0.15rem 0.4rem !important;
}
pre {
    background: #0d1117 !important;
    border: 1px solid #21262d !important;
    border-radius: 8px !important;
    padding: 1rem !important;
}

/* ── Spinner ── */
.stSpinner > div { border-top-color: #388bfd !important; }

/* ── Footer ── */
.footer {
    text-align: center;
    color: #484f58;
    font-size: 0.78rem;
    padding: 2rem 0 1rem;
    border-top: 1px solid #21262d;
    margin-top: 2.5rem;
}
.footer a { color: #388bfd; text-decoration: none; }
.footer a:hover { text-decoration: underline; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }
</style>
""", unsafe_allow_html=True)

# ── Load model ────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def load_model():
    return joblib.load("../models/phishing_model.pkl")

try:
    model = load_model()
    model_loaded = True
except Exception as e:
    model_loaded = False
    model_error = str(e)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="padding: 0.5rem 0 1.5rem;">
        <div style="font-size:1.6rem; font-weight:800; color:#e6edf3; letter-spacing:-0.5px;">
            🛡️ PhishGuard AI
        </div>
        <div style="font-size:0.75rem; color:#8b949e; margin-top:0.2rem;">
            URL Threat Intelligence Platform
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### How It Works")
    st.markdown("""
    <div style="font-size:0.83rem; color:#8b949e; line-height:1.7;">
    <b style="color:#c9d1d9;">1. Feature Extraction</b><br>
    Parses structural, lexical, and host-based signals from the URL.<br><br>
    <b style="color:#c9d1d9;">2. ML Prediction</b><br>
    A trained Random Forest classifier scores benign vs. phishing probability.<br><br>
    <b style="color:#c9d1d9;">3. VirusTotal Scan</b><br>
    Cross-references 90+ AV engines via the VirusTotal API.<br><br>
    <b style="color:#c9d1d9;">4. Risk Score</b><br>
    Fuses ML and VT signals into a final risk tier.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### Model Status")
    if model_loaded:
        st.success("✅  Random Forest loaded")
        st.markdown(f"<div style='font-size:0.78rem; color:#8b949e;'>Classes: <code>benign</code> · <code>phishing</code></div>", unsafe_allow_html=True)
    else:
        st.error("❌  Model failed to load")
        st.code(model_error, language="text")

    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    <div style="font-size:0.78rem; color:#8b949e; line-height:1.7;">
    Built with Python · Streamlit · Scikit-learn<br>
    Threat data powered by VirusTotal API.<br><br>
    <span style="color:#484f58;">For educational and research use.</span>
    </div>
    """, unsafe_allow_html=True)

# ── Main header ───────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding: 1.5rem 0 0.5rem;">
    <div style="font-size:0.72rem; font-weight:600; text-transform:uppercase;
                letter-spacing:2px; color:#388bfd; margin-bottom:0.5rem;">
        AI-Powered Cybersecurity Tool
    </div>
    <h1 style="font-size:2.1rem; font-weight:800; margin:0; line-height:1.2;">
        URL Phishing Detection System
    </h1>
    <p style="color:#8b949e; font-size:0.92rem; margin-top:0.5rem;">
        Analyze any URL with machine learning and live VirusTotal threat intelligence.
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown("<div style='height:4px; background:linear-gradient(90deg,#1f6feb,#388bfd,#79c0ff,#0a0c10); border-radius:2px; margin-bottom:1.5rem;'></div>", unsafe_allow_html=True)

# ── URL input ─────────────────────────────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])
with col_input:
    url_input = st.text_input(
        label="Target URL",
        placeholder="https://example.com/login?redirect=...",
        label_visibility="collapsed",
    )
with col_btn:
    analyze_clicked = st.button("🔍 Analyze", use_container_width=True)

st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)

# ── Guard: model must be loaded ───────────────────────────────────────────────
if not model_loaded:
    st.error("Cannot proceed — model file not found. Check `../models/phishing_model.pkl`.")
    st.stop()

# ── Analysis ──────────────────────────────────────────────────────────────────
if analyze_clicked:
    if not url_input.strip():
        st.warning("⚠️  Please enter a URL before clicking Analyze.")
        st.stop()

    # ── Initialize all result variables up front ──────────────────────────────
    features = []
    prediction = "benign"
    safe_prob = 0.0
    phishing_prob = 0.0
    vt_result = {"malicious": 0, "suspicious": 0, "harmless": 0}
    malicious = 0
    suspicious = 0
    harmless = 0
    risk = "LOW"
    analysis_error = None

    with st.spinner("🔄  Extracting features, running inference, querying VirusTotal…"):
        try:
            # Step 1 – feature extraction
            features = extract_features(url_input.strip())

            # Step 2 – ML inference
            prediction = model.predict([features])[0]
            probabilities = model.predict_proba([features])[0]
            class_probs = dict(zip(model.classes_, probabilities))
            safe_prob = class_probs.get("benign", 0.0) * 100
            phishing_prob = class_probs.get("phishing", 0.0) * 100

            # Step 3 – VirusTotal
            vt_result = scan_url(url_input.strip())
            if not isinstance(vt_result, dict):
                vt_result = {"malicious": 0, "suspicious": 0, "harmless": 0}
            malicious = int(vt_result.get("malicious", 0))
            suspicious = int(vt_result.get("suspicious", 0))
            harmless = int(vt_result.get("harmless", 0))

            # Step 4 – Risk engine
            risk = calculate_risk(prediction, vt_result)
            if not isinstance(risk, str):
                risk = str(risk)
            risk = risk.upper()

        except Exception as exc:
            analysis_error = str(exc)

    # ── Error state ───────────────────────────────────────────────────────────
    if analysis_error:
        st.error(f"Analysis failed: {analysis_error}")
        st.stop()

    # ─────────────────────────────────────────────────────────────────────────
    # RESULTS LAYOUT
    # ─────────────────────────────────────────────────────────────────────────

    # ── Analyzed URL banner ───────────────────────────────────────────────────
    st.markdown(f"""
    <div class="card" style="display:flex; align-items:center; gap:1rem;">
        <div style="font-size:1.3rem;">🔗</div>
        <div>
            <div class="card-header">Analyzed URL</div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.88rem;
                        color:#79c0ff; word-break:break-all;">{url_input.strip()}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ─── Section 1: AI Model Results ─────────────────────────────────────────
    st.markdown('<div class="section-label">🤖 &nbsp;AI Model Analysis</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 1.4])

    with col1:
        st.markdown(f"""
        <div class="card">
            <div class="card-header">Safe Probability</div>
            <div class="card-value" style="color:#3fb950;">{safe_prob:.1f}%</div>
            <div class="card-sub">Benign classification confidence</div>
        </div>
        """, unsafe_allow_html=True)
        st.progress(min(safe_prob / 100, 1.0))

    with col2:
        st.markdown(f"""
        <div class="card">
            <div class="card-header">Phishing Probability</div>
            <div class="card-value" style="color:#f85149;">{phishing_prob:.1f}%</div>
            <div class="card-sub">Phishing classification confidence</div>
        </div>
        """, unsafe_allow_html=True)
        st.progress(min(phishing_prob / 100, 1.0))

    with col3:
        if prediction == "benign":
            st.markdown(f"""
            <div class="pred-safe">
                <div class="pred-icon">✅</div>
                <div class="pred-label">SAFE</div>
                <div class="pred-note">Model classified this URL as benign</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="pred-phishing">
                <div class="pred-icon">🚨</div>
                <div class="pred-label">PHISHING DETECTED</div>
                <div class="pred-note">Model flagged this URL as a phishing threat</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)

    # ─── Section 2: VirusTotal Results ───────────────────────────────────────
    st.markdown('<div class="section-label">🛡️ &nbsp;VirusTotal Intelligence</div>', unsafe_allow_html=True)

    vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)

    with vt_col1:
        st.markdown(f"""
        <div class="vt-box vt-malicious">
            <div class="vt-box-label">Malicious</div>
            <div class="vt-box-value">{malicious}</div>
        </div>
        """, unsafe_allow_html=True)

    with vt_col2:
        st.markdown(f"""
        <div class="vt-box vt-suspicious">
            <div class="vt-box-label">Suspicious</div>
            <div class="vt-box-value">{suspicious}</div>
        </div>
        """, unsafe_allow_html=True)

    with vt_col3:
        st.markdown(f"""
        <div class="vt-box vt-harmless">
            <div class="vt-box-label">Harmless</div>
            <div class="vt-box-value">{harmless}</div>
        </div>
        """, unsafe_allow_html=True)

    with vt_col4:
        total_vt = malicious + suspicious + harmless
        st.markdown(f"""
        <div class="vt-box" style="">
            <div class="vt-box-label">Total Engines</div>
            <div class="vt-box-value" style="color:#8b949e;">{total_vt}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:1rem;'></div>", unsafe_allow_html=True)

    # ─── Section 3: Donut chart + Risk ───────────────────────────────────────
    st.markdown('<div class="section-label">📊 &nbsp;Threat Breakdown</div>', unsafe_allow_html=True)

    chart_col, risk_col = st.columns([1.4, 1])

    with chart_col:
        total_chart = malicious + suspicious + harmless
        if total_chart == 0:
            chart_values = [1, 1, 1]
            chart_note = "(No VT engine data returned)"
        else:
            chart_values = [malicious, suspicious, harmless]
            chart_note = ""

        fig = go.Figure(data=[go.Pie(
            labels=["Malicious", "Suspicious", "Harmless"],
            values=chart_values,
            hole=0.62,
            marker=dict(
                colors=["#f85149", "#f0883e", "#3fb950"],
                line=dict(color="#0a0c10", width=2),
            ),
            textinfo="label+percent",
            textfont=dict(size=12, color="#c9d1d9"),
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
        )])

        fig.add_annotation(
            text=f"<b>{total_chart}</b><br><span style='font-size:11px'>Engines</span>",
            x=0.5, y=0.5, font=dict(size=18, color="#e6edf3"),
            showarrow=False, align="center",
        )

        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=True,
            legend=dict(
                orientation="v",
                x=1.02, y=0.5,
                font=dict(color="#8b949e", size=12),
                bgcolor="rgba(0,0,0,0)",
            ),
            margin=dict(t=20, b=20, l=20, r=20),
            height=280,
        )

        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        if chart_note:
            st.caption(chart_note)

    with risk_col:
        risk_map = {
            "LOW": {
                "cls": "risk-low",
                "icon": "🟢",
                "desc": "No significant threat signals detected. URL appears safe.",
            },
            "MEDIUM": {
                "cls": "risk-medium",
                "icon": "🟡",
                "desc": "Some suspicious indicators found. Exercise caution.",
            },
            "HIGH": {
                "cls": "risk-high",
                "icon": "🟠",
                "desc": "Multiple threat signals detected. Avoid this URL.",
            },
            "CRITICAL": {
                "cls": "risk-critical",
                "icon": "🔴",
                "desc": "URL confirmed malicious. Do not visit.",
            },
        }

        r = risk_map.get(risk, risk_map["LOW"])
        st.markdown(f"""
        <div class="{r['cls']}" style="margin-top:0.5rem;">
            <div class="risk-title">Risk Assessment</div>
            <div class="risk-value">{r['icon']} {risk}</div>
            <div class="risk-desc">{r['desc']}</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)

        # Probability bars side by side as a mini table
        st.markdown(f"""
        <div class="card" style="padding:1rem 1.2rem;">
            <div class="card-header">Model Confidence</div>
            <div style="margin-top:0.6rem;">
                <div style="display:flex; justify-content:space-between;
                            font-size:0.8rem; color:#8b949e; margin-bottom:2px;">
                    <span>Benign</span><span style="color:#3fb950;">{safe_prob:.1f}%</span>
                </div>
                <div style="height:6px; background:#21262d; border-radius:3px; margin-bottom:0.6rem;">
                    <div style="width:{safe_prob:.1f}%; height:100%;
                                background:#3fb950; border-radius:3px;"></div>
                </div>
                <div style="display:flex; justify-content:space-between;
                            font-size:0.8rem; color:#8b949e; margin-bottom:2px;">
                    <span>Phishing</span><span style="color:#f85149;">{phishing_prob:.1f}%</span>
                </div>
                <div style="height:6px; background:#21262d; border-radius:3px;">
                    <div style="width:{phishing_prob:.1f}%; height:100%;
                                background:#f85149; border-radius:3px;"></div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)

    # ─── Section 4: Technical Details expander ───────────────────────────────
    with st.expander("🔬  Technical Details", expanded=False):
        tech_c1, tech_c2 = st.columns(2)

        with tech_c1:
            st.markdown("**Feature Vector**")
            if isinstance(features, (list, tuple)) and len(features) > 0:
                feature_df = pd.DataFrame(
                    {"Index": list(range(len(features))), "Value": list(features)}
                )
                st.dataframe(
                    feature_df,
                    use_container_width=True,
                    hide_index=True,
                    height=280,
                )
            else:
                st.info("Feature vector unavailable.")

            st.markdown("**Model Classes**")
            classes_list = list(model.classes_)
            st.code(str(classes_list), language="python")

        with tech_c2:
            st.markdown("**VirusTotal Raw Response**")
            st.json(vt_result)

            st.markdown("**Inference Summary**")
            st.code(
                f"prediction   = '{prediction}'\n"
                f"safe_prob    = {safe_prob:.4f}%\n"
                f"phishing_prob= {phishing_prob:.4f}%\n"
                f"risk_level   = '{risk}'\n"
                f"vt_malicious = {malicious}\n"
                f"vt_suspicious= {suspicious}\n"
                f"vt_harmless  = {harmless}",
                language="python",
            )

# ── Empty state ───────────────────────────────────────────────────────────────
else:
    st.markdown("""
    <div style="text-align:center; padding:4rem 2rem 3rem;">
        <div style="font-size:4rem; margin-bottom:1rem;">🔍</div>
        <div style="font-size:1.1rem; font-weight:600; color:#c9d1d9; margin-bottom:0.5rem;">
            Enter a URL to begin threat analysis
        </div>
        <div style="font-size:0.85rem; color:#484f58; max-width:420px; margin:0 auto; line-height:1.6;">
            Paste any URL into the input above and click <strong style="color:#388bfd;">Analyze</strong>.
            Results include ML classification, VirusTotal scan data, and a fused risk score.
        </div>
    </div>
    """, unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    PhishGuard AI &nbsp;·&nbsp; Built with
    <a href="https://streamlit.io" target="_blank">Streamlit</a>,
    <a href="https://scikit-learn.org" target="_blank">Scikit-learn</a> &amp;
    <a href="https://www.virustotal.com" target="_blank">VirusTotal API</a>
    &nbsp;·&nbsp; For educational and research purposes only.
</div>
""", unsafe_allow_html=True)

