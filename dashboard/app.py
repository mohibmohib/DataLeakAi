"""DataLeak AI - Streamlit dashboard.

Run from the project root:   streamlit run dashboard/app.py
"""
import json
import sys
import uuid
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.gateway import DataLeakGateway          # noqa: E402
from src.policy_engine import DEFAULT_POLICY    # noqa: E402
from src import database as db                   # noqa: E402

st.set_page_config(page_title="DataLeak AI", page_icon="🛡️", layout="wide")

POLICY_FILE = ROOT / "logs" / "policy.json"
RAW_DIR = ROOT / "data" / "raw"
PROC_DIR = ROOT / "data" / "processed"

ACTION_ORDER = ["ALLOW", "WARN", "REDACT", "BLOCK"]
ACTION_COLORS = {"ALLOW": "#2e9e5b", "WARN": "#e0a526", "REDACT": "#e07a26", "BLOCK": "#d64545"}
ACTION_ICONS = {"ALLOW": "✅", "WARN": "⚠️", "REDACT": "✂️", "BLOCK": "🚨"}
LEVEL_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

EXAMPLES = {
    "Safe question": "Explain how machine learning works.",
    "Personal information": "Analyze Ahmed Khan's CNIC 35202-1234567-1 and phone 0300-1234567.",
    "API credential": "Debug my application using this API key AKIAIOSFODNN7EXAMPLE",
    "Source code": "Analyze our confidential authentication source code and find vulnerabilities.",
    "Email only (warn)": "Please email me at test@gmail.com",
    "Credit card": "Reconcile this payment: card 4111 1111 1111 1111 exp 09/28.",
}

DEMO_PROMPTS = list(EXAMPLES.values()) + [
    "Write a Python function that checks whether a number is prime.",
    "How do I report a phishing email to my IT department?",
    "Customer Sana Tariq, CNIC 42101-7654321-0, called about a refund. Summarize the case.",
    "mongodb://admin:Sup3rS3cret@10.0.0.5:27017/prod fails to connect, help.",
    "Summarize this confidential HR investigation report about a senior manager.",
    "Our server is at 192.168.1.20, help me configure SSH.",
]


# ----------------------------------------------------------------- setup
def load_policy() -> dict:
    policy = dict(DEFAULT_POLICY)
    try:
        if POLICY_FILE.exists():
            policy.update(json.loads(POLICY_FILE.read_text()))
    except Exception:
        pass
    return policy


def save_policy(policy: dict) -> None:
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(json.dumps(policy, indent=2))


@st.cache_resource(show_spinner="Loading models...")
def get_gateway() -> DataLeakGateway:
    return DataLeakGateway()


gw = get_gateway()
if "policy" not in st.session_state:
    st.session_state.policy = load_policy()
if "sid" not in st.session_state:
    st.session_state.sid = "sess-" + uuid.uuid4().hex[:8]
gw.policy = st.session_state.policy


def simulated_ai(prompt: str) -> str:
    """Stand-in for the external AI. Replace with a real API call later."""
    return (f"(Simulated assistant) I received your request ({len(prompt.split())} words) "
            "and would answer it here.")


# --------------------------------------------------------------- helpers
def count_df(series: pd.Series, col: str, order=None) -> pd.DataFrame:
    out = series.value_counts().rename_axis(col).reset_index(name="count")
    if order:
        out[col] = pd.Categorical(out[col], categories=order, ordered=True)
        out = out.sort_values(col)
    return out


def load_events() -> pd.DataFrame:
    df = db.events_df()
    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df


def empty_state():
    st.info("No events yet. Analyze a prompt, or load sample data from **Settings**.")


# ------------------------------------------------------------ page: home
def page_dashboard():
    st.title("🛡️ DataLeak AI")
    st.caption("AI Security & Data Loss Prevention Dashboard")
    summary = db.summary()
    if summary["total"] == 0:
        return empty_state()

    cols = st.columns(5)
    cols[0].metric("Requests", f"{summary['total']:,}")
    for col, action in zip(cols[1:], ACTION_ORDER):
        col.metric({"ALLOW": "Allowed", "WARN": "Warnings", "REDACT": "Redacted", "BLOCK": "Blocked"}[action],
                   f"{summary[action]:,}")

    df = load_events()
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Requests over time")
        tmp = df.assign(bucket=df["ts"].dt.floor("h"))
        per = tmp.groupby(["bucket", "action"]).size().reset_index(name="count")
        fig = px.bar(per, x="bucket", y="count", color="action",
                     color_discrete_map=ACTION_COLORS, category_orders={"action": ACTION_ORDER})
        fig.update_layout(xaxis_title=None, legend_title=None, margin=dict(t=10))
        st.plotly_chart(fig)
    with c2:
        st.subheader("Actions taken")
        fig = px.pie(count_df(df["action"], "action", ACTION_ORDER), names="action", values="count",
                     color="action", color_discrete_map=ACTION_COLORS, hole=0.45)
        fig.update_layout(margin=dict(t=10))
        st.plotly_chart(fig)

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Threat categories")
        fig = px.bar(count_df(df["category"], "category"), x="category", y="count", color="category")
        fig.update_layout(showlegend=False, xaxis_title=None, margin=dict(t=10))
        st.plotly_chart(fig)
    with c4:
        st.subheader("Risk levels")
        fig = px.bar(count_df(df["risk_level"], "risk_level", LEVEL_ORDER), x="risk_level", y="count")
        fig.update_layout(xaxis_title=None, margin=dict(t=10))
        st.plotly_chart(fig)


# ------------------------------------------------------- page: analyze
def _load_example():
    choice = st.session_state.get("example", "—")
    if choice in EXAMPLES:
        st.session_state.prompt_box = EXAMPLES[choice]


def _choose(choice: str):
    if st.session_state.get("last"):
        st.session_state.last["choice"] = choice


def render_result(last: dict):
    r, risk, act = last["result"], last["result"]["risk"], last["result"]["action"]
    color = ACTION_COLORS[act]
    st.markdown(
        f"<div style='padding:14px 18px;border-radius:8px;background:{color}22;border-left:6px solid {color}'>"
        f"<b style='color:{color};font-size:1.3em'>{ACTION_ICONS[act]} {act}</b>"
        f"&nbsp;&nbsp; Risk {risk['score']}/100 ({risk['level']}) &middot; {r['decision']['reason']}</div>",
        unsafe_allow_html=True)
    st.write("")

    m = st.columns(4)
    m[0].metric("Risk score", f"{risk['score']}/100")
    m[1].metric("Risk level", risk["level"])
    m[2].metric("Category", risk["category"])
    m[3].metric("ML prediction", f"{risk['ml_label']} ({risk['ml_confidence']:.0%})")

    left, right = st.columns(2)
    with left:
        st.subheader("Why this decision")
        st.code(r["explanation"], language=None)
    with right:
        st.subheader("Detected items")
        if r["entities"]:
            ents = pd.DataFrame(r["entities"])[["type", "category", "severity"]]
            st.dataframe(ents, hide_index=True)
        else:
            st.write("No pattern-based sensitive data found.")

    st.divider()
    sanitized = r.get("sanitized_prompt")
    forwarded = None

    if act == "ALLOW":
        forwarded = last["prompt"]
    elif act == "REDACT":
        st.subheader("Sanitized prompt (what the AI will see)")
        st.code(sanitized or "", language=None)
        forwarded = sanitized
    elif act == "WARN":
        choice = last.get("choice")
        if choice is None:
            st.warning("This request may contain sensitive content. You can continue as-is, "
                       "or let DataLeak AI redact it first.")
            b1, b2, _ = st.columns([1, 1, 4])
            b1.button("Continue", on_click=_choose, args=("continue",), key="btn_continue")
            b2.button("Redact", on_click=_choose, args=("redact",), key="btn_redact")
        elif choice == "continue":
            forwarded = last["prompt"]
        else:
            forwarded = sanitized or last["prompt"]
            st.subheader("Sanitized prompt (what the AI will see)")
            st.code(forwarded, language=None)
    else:  # BLOCK
        st.error("Request blocked. Nothing was sent to the external AI. "
                 "Remove the sensitive content and try again.")

    if forwarded is not None:
        st.subheader("Response from the AI")
        st.write(simulated_ai(forwarded))


def page_analyze():
    st.title("Analyze Prompt")
    st.caption("Everything you type here is checked before it would reach an external AI.")
    st.selectbox("Load an example", ["—"] + list(EXAMPLES), key="example", on_change=_load_example)
    prompt = st.text_area("Prompt", height=170, key="prompt_box",
                          placeholder="Type or paste the prompt an employee wants to send...")
    if st.button("Analyze", type="primary"):
        if not prompt.strip():
            st.warning("Please enter a prompt first.")
        else:
            with st.spinner("Analyzing..."):
                result = gw.analyze(prompt)
            db.log_event(prompt, result, st.session_state.sid)
            st.session_state.last = {"prompt": prompt, "result": result, "choice": None}
    if st.session_state.get("last"):
        render_result(st.session_state.last)


# ------------------------------------------------------- page: events
def page_events():
    st.title("Security Events")
    df = load_events()
    if df.empty:
        return empty_state()
    st.caption("Raw prompts are never stored. Each event keeps metadata, a keyed hash, "
               "and the redacted text only.")

    f1, f2, f3 = st.columns(3)
    actions = f1.multiselect("Action", ACTION_ORDER, default=ACTION_ORDER)
    cats = f2.multiselect("Category", sorted(df["category"].dropna().unique()),
                          default=sorted(df["category"].dropna().unique()))
    min_risk = f3.slider("Minimum risk score", 0, 100, 0)

    view = df[df["action"].isin(actions) & df["category"].isin(cats) & (df["risk_score"] >= min_risk)]
    cols = ["ts", "session_id", "category", "risk_score", "risk_level", "action",
            "ml_label", "ml_confidence", "entity_types", "redacted_text"]
    st.write(f"Showing {len(view):,} of {len(df):,} events")
    st.dataframe(view[cols], hide_index=True)
    st.download_button("Download CSV", view[cols].to_csv(index=False).encode(), "security_events.csv", "text/csv")


# --------------------------------------------------- page: analytics
def page_analytics():
    st.title("Threat Analytics")
    df = load_events()
    if df.empty:
        return empty_state()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Detected data types")
        types = df["entity_types"].fillna("").str.split(",").explode().str.strip()
        types = types[types != ""]
        if types.empty:
            st.write("No pattern-based detections yet.")
        else:
            fig = px.bar(count_df(types, "type"), x="count", y="type", orientation="h")
            fig.update_layout(yaxis_title=None, margin=dict(t=10))
            st.plotly_chart(fig)
    with c2:
        st.subheader("Risk score distribution")
        fig = px.histogram(df, x="risk_score", color="action", nbins=20,
                           color_discrete_map=ACTION_COLORS, category_orders={"action": ACTION_ORDER})
        fig.update_layout(legend_title=None, margin=dict(t=10))
        st.plotly_chart(fig)

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Category vs action")
        ct = pd.crosstab(df["category"], df["action"]).reindex(columns=ACTION_ORDER, fill_value=0)
        fig = px.imshow(ct, text_auto=True, aspect="auto", color_continuous_scale="Blues")
        fig.update_layout(margin=dict(t=10))
        st.plotly_chart(fig)
    with c4:
        st.subheader("ML model confidence")
        fig = px.box(df, x="ml_label", y="ml_confidence")
        fig.update_layout(xaxis_title=None, margin=dict(t=10))
        st.plotly_chart(fig)

    st.subheader("Highest-risk events")
    st.dataframe(df.sort_values("risk_score", ascending=False).head(10)
                 [["ts", "category", "risk_score", "action", "entity_types"]], hide_index=True)


# ------------------------------------------------------ page: model
def evaluate_holdout() -> pd.DataFrame:
    path = RAW_DIR / "holdout_test.csv"
    ho = pd.read_csv(path)
    res = [gw.analyze(p) for p in ho["prompt"]]
    ho["got"] = [r["action"] for r in res]
    ho["score"] = [r["risk"]["score"] for r in res]
    return ho


def page_model():
    st.title("Model Performance")

    st.subheader("Classifier comparison (Colab experiments)")
    cmp_path = PROC_DIR / "model_comparison_v2.csv"
    if cmp_path.exists():
        cmp = pd.read_csv(cmp_path)
        st.dataframe(cmp, hide_index=True)
        melted = cmp.melt(id_vars="Model", var_name="Metric", value_name="F1")
        fig = px.bar(melted, x="Model", y="F1", color="Metric", barmode="group")
        fig.update_layout(margin=dict(t=10), legend_title=None)
        st.plotly_chart(fig)
        st.caption("CV and validation scores use synthetic data and are near 1.0. "
                   "The real-world column is the honest measure.")
    else:
        st.info(f"Copy model_comparison_v2.csv into {PROC_DIR} to show the model comparison.")

    st.subheader("End-to-end evaluation on held-out prompts")
    st.caption("Runs the full pipeline (detectors + ML + risk + policy) on data/raw/holdout_test.csv. "
               "Results depend on the current policy thresholds.")
    if not (RAW_DIR / "holdout_test.csv").exists():
        st.info("data/raw/holdout_test.csv not found.")
        return
    if st.button("Run evaluation"):
        with st.spinner("Evaluating..."):
            st.session_state.holdout = evaluate_holdout()
    ho = st.session_state.get("holdout")
    if ho is not None:
        sens = ho["label"] != "safe"
        m = st.columns(4)
        m[0].metric("Exact action accuracy", f"{(ho['expected'] == ho['got']).mean():.0%}")
        m[1].metric("Leak catch rate", f"{ho[sens]['got'].isin(['REDACT', 'BLOCK']).mean():.0%}")
        m[2].metric("False block rate", f"{ho[~sens]['got'].isin(['REDACT', 'BLOCK']).mean():.0%}")
        m[3].metric("Prompts tested", len(ho))
        ct = pd.crosstab(ho["expected"], ho["got"]).reindex(index=ACTION_ORDER, columns=ACTION_ORDER, fill_value=0)
        fig = px.imshow(ct, text_auto=True, aspect="auto", color_continuous_scale="Blues",
                        labels=dict(x="System action", y="Expected action"))
        st.plotly_chart(fig)
        wrong = ho[ho["expected"] != ho["got"]][["prompt", "expected", "got", "score"]]
        if len(wrong):
            st.write("Mismatches")
            st.dataframe(wrong, hide_index=True)


# ---------------------------------------------------- page: settings
def page_settings():
    st.title("Settings")
    pol = dict(st.session_state.policy)

    st.subheader("Decision thresholds")
    st.caption("Configurable per organization. These are defaults for this project, not an industry standard.")
    c1, c2, c3 = st.columns(3)
    allow_max = c1.number_input("ALLOW up to", 0, 98, int(pol["allow_max"]))
    warn_max = c2.number_input("WARN up to", 1, 99, int(pol["warn_max"]))
    redact_max = c3.number_input("REDACT up to (above = BLOCK)", 2, 100, int(pol["redact_max"]))
    st.write(f"ALLOW 0-{allow_max} · WARN {allow_max + 1}-{warn_max} · "
             f"REDACT {warn_max + 1}-{redact_max} · BLOCK {redact_max + 1}-100")

    b1, b2, _ = st.columns([1, 1, 4])
    if b1.button("Save thresholds", type="primary"):
        if not allow_max < warn_max < redact_max:
            st.error("Thresholds must increase: ALLOW < WARN < REDACT.")
        else:
            pol.update(allow_max=int(allow_max), warn_max=int(warn_max), redact_max=int(redact_max))
            st.session_state.policy = pol
            save_policy(pol)
            st.success("Saved.")
    if b2.button("Reset to defaults"):
        st.session_state.policy = dict(DEFAULT_POLICY)
        save_policy(st.session_state.policy)
        st.rerun()

    st.divider()
    st.subheader("Demo data")
    st.caption("Runs sample prompts through the gateway and logs them, so the dashboard has data for a demo.")
    if st.button("Load sample prompts"):
        prompts = list(DEMO_PROMPTS)
        for name in ("realworld_test.csv", "holdout_test.csv"):
            p = RAW_DIR / name
            if p.exists():
                prompts += pd.read_csv(p)["prompt"].tolist()
        bar = st.progress(0.0)
        for i, text in enumerate(prompts, 1):
            db.log_event(text, gw.analyze(text), "demo")
            bar.progress(i / len(prompts))
        st.success(f"Logged {len(prompts)} sample events.")

    st.divider()
    st.subheader("Danger zone")
    confirm = st.checkbox("I understand this deletes all logged events")
    if st.button("Clear all events", disabled=not confirm):
        db.reset_db()
        st.success("All events deleted.")


# ------------------------------------------------------------ router
PAGES = {
    "Dashboard": page_dashboard,
    "Analyze Prompt": page_analyze,
    "Security Events": page_events,
    "Threat Analytics": page_analytics,
    "Model Performance": page_model,
    "Settings": page_settings,
}

with st.sidebar:
    st.header("🛡️ DataLeak AI")
    page = st.radio("Navigation", list(PAGES), label_visibility="collapsed")
    st.divider()
    pol = st.session_state.policy
    st.caption(f"Policy: ALLOW ≤{pol['allow_max']} · WARN ≤{pol['warn_max']} · REDACT ≤{pol['redact_max']}")
    st.caption("Raw prompts are not stored in the logs.")

PAGES[page]()
