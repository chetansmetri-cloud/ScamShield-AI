import html
import csv
import base64
import io
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
import plotly.graph_objects as go
import streamlit as st
from frontend.api_client import authorization_headers

API_BASE_URL = os.getenv("SCAMSHIELD_API_URL", "http://127.0.0.1:8000").rstrip("/")
APP_ROOT = Path(__file__).resolve().parent.parent
NAVIGATION = [
    "Overview",
    "New investigation",
    "URL scanner",
    "Message scanner",
    "Job scam detector",
    "Email scam detection",
    "Payment scam checker",
    "Email intelligence",
    "Phone intelligence",
    "Company intelligence",
    "Domain intelligence",
    "Screenshot analyzer",
    "QR scanner",
    "AI security assistant",
    "Batch URL investigation",
    "Threat intelligence",
    "Evidence graph",
    "Investigation timeline",
    "History",
    "Saved reports",
    "Watchlist",
    "Scam alerts",
    "Analytics",
    "Profile",
    "Settings",
    "Integrations",
    "Risk methodology",
    "Help & support",
]
RISK_COLORS = {
    "Low risk indicators": "#C7F000",
    "Some concerns": "#A9BAFF",
    "Suspicious": "#2457FF",
    "High risk indicators": "#101828",
    "Insufficient evidence": "#667085",
}

st.set_page_config(
    page_title="ScamShield AI | Threat Intelligence",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="collapsed",
)

theme_path = Path(__file__).with_name("theme.css")
st.markdown(
    f"<style>{theme_path.read_text(encoding='utf-8')}</style>",
    unsafe_allow_html=True,
)


def api_call(method: str, route: str, **kwargs: Any) -> Any:
    timeout = kwargs.pop("timeout", 90)
    headers = authorization_headers(
        st.session_state.get("auth_token"),
        kwargs.pop("headers", {}),
    )
    try:
        response = httpx.request(
            method,
            f"{API_BASE_URL}{route}",
            timeout=timeout,
            headers=headers,
            **kwargs,
        )
    except httpx.TimeoutException:
        st.error("The service took too long to respond. Retry when it is available.")
        return None
    except httpx.RequestError as exc:
        st.error(
            f"Cannot reach the ScamShield backend ({type(exc).__name__}). "
            "Check service status and retry."
        )
        return None

    if not response.is_success:
        try:
            data = response.json()
            message = data.get("detail", "Request failed.") if isinstance(data, dict) else "Request failed."
        except ValueError:
            message = "Request failed."
        st.error(str(message))
        return None
    if response.status_code == 204:
        return {}
    try:
        return response.json()
    except ValueError:
        st.error("The backend returned an unreadable response.")
        return None


def service_status() -> tuple[bool, str]:
    try:
        response = httpx.get(f"{API_BASE_URL}/health", timeout=3)
    except httpx.RequestError:
        return False, "API offline"
    if not response.is_success:
        return False, "API unavailable"
    try:
        payload = response.json()
    except ValueError:
        return False, "API unavailable"
    return payload.get("status") == "ok", "All systems operational"


def risk_color(category: str) -> str:
    return RISK_COLORS.get(category, "#2457FF")


def chart_layout(**overrides: Any) -> dict[str, Any]:
    return {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {"family": "Inter, sans-serif", "color": "#a7b3c6", "size": 12},
        "margin": {"l": 8, "r": 8, "t": 24, "b": 8},
        **overrides,
    }


def render_brand() -> None:
    st.sidebar.markdown(
        """
        <div class="brand-lockup">
          <div class="brand-mark">
            <svg viewBox="0 0 48 48" aria-hidden="true">
              <path d="M24 4 41 11v12c0 11-7.4 17.8-17 22C14.4 40.8 7 34 7 23V11z"
                fill="none" stroke="url(#shield-gradient)" stroke-width="2.8"/>
              <path d="m16 24 5 5 11-12" fill="none" stroke="#C7F000"
                stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
              <defs><linearGradient id="shield-gradient" x1="7" y1="4" x2="42" y2="44">
                <stop stop-color="#2457FF"/><stop offset="1" stop-color="#C7F000"/>
              </linearGradient></defs>
            </svg>
          </div>
          <div><strong>SCAMSHIELD</strong><span>THREAT INTELLIGENCE</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_ambient_scene(kind: str) -> None:
    scene_class = {
        "auth": "ambient-scene--auth",
        "landing": "ambient-scene--landing",
        "workspace": "ambient-scene--workspace",
    }.get(kind, "ambient-scene--landing")
    particle_positions = (
        (7, 18, 5, 17), (14, 73, 11, 21), (22, 38, 17, 19),
        (29, 86, 7, 23), (36, 22, 13, 18), (43, 62, 3, 22),
        (51, 14, 19, 20), (58, 79, 9, 24), (66, 34, 15, 18),
        (73, 91, 4, 21), (81, 26, 12, 23), (89, 68, 18, 19),
        (95, 43, 8, 22), (18, 51, 2, 20), (47, 91, 16, 24),
        (77, 54, 6, 18),
    )
    particles = "".join(
        f'<span class="ambient-particle ambient-particle--field" style="--particle-x:{x}%;--particle-y:{y}%;'
        f'--particle-delay:-{delay}s;--particle-duration:{duration}s"></span>'
        for x, y, delay, duration in particle_positions
    )
    st.markdown(
        f"""
        <div class="ambient-scene {scene_class}" aria-hidden="true">
          <div class="ambient-aurora"></div>
          <div class="ambient-energy ambient-energy--one"></div>
          <div class="ambient-energy ambient-energy--two"></div>
          <div class="ambient-orb ambient-orb--blue"></div>
          <div class="ambient-orb ambient-orb--lime"></div>
          <div class="ambient-ring ambient-ring--one"></div>
          <div class="ambient-ring ambient-ring--two"></div>
          <svg class="ambient-network" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
            <path d="M75 170 280 260 460 110 670 250 870 135 1110 270M160 590 350 450 555 650 760 470 980 610 1130 480M280 260 350 450 670 250 760 470 870 135" />
            <g><circle cx="75" cy="170" r="4"/><circle cx="280" cy="260" r="5"/>
              <circle cx="460" cy="110" r="4"/><circle cx="670" cy="250" r="5"/>
              <circle cx="870" cy="135" r="4"/><circle cx="1110" cy="270" r="5"/>
              <circle cx="160" cy="590" r="4"/><circle cx="350" cy="450" r="5"/>
              <circle cx="555" cy="650" r="4"/><circle cx="760" cy="470" r="5"/>
              <circle cx="980" cy="610" r="4"/><circle cx="1130" cy="480" r="4"/>
            </g>
          </svg>
          {particles}
          <span class="ambient-particle ambient-particle--one"></span>
          <span class="ambient-particle ambient-particle--two"></span>
          <span class="ambient-particle ambient-particle--three"></span>
          <span class="ambient-particle ambient-particle--four"></span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar() -> str:
    render_brand()
    st.sidebar.markdown('<div class="nav-caption">WORKSPACE</div>', unsafe_allow_html=True)
    if "pending_navigation" in st.session_state:
        st.session_state["main_navigation"] = st.session_state.pop("pending_navigation")
    navigation = list(NAVIGATION)
    user = st.session_state.get("account", {})
    if user.get("role") == "admin":
        navigation.append("Admin")
    selected = st.sidebar.radio(
        "Workspace",
        navigation,
        label_visibility="collapsed",
        key="main_navigation",
        format_func=lambda value: {
            "Overview": "01  Overview",
            "New investigation": "02  New investigation",
            "URL scanner": "03  URL scanner",
            "Message scanner": "04  Message scanner",
            "Job scam detector": "05  Job scam detector",
            "Email scam detection": "06  Email scam detection",
            "Payment scam checker": "07  Payment scam checker",
            "Email intelligence": "08  Email intelligence",
            "Phone intelligence": "09  Phone intelligence",
            "Company intelligence": "10  Company intelligence",
            "Domain intelligence": "11  Domain intelligence",
            "Screenshot analyzer": "12  Screenshot analyzer",
            "QR scanner": "13  QR scanner",
            "AI security assistant": "14  AI security assistant",
            "Batch URL investigation": "15  Batch URL investigation",
            "Threat intelligence": "16  Threat intelligence",
            "Evidence graph": "17  Evidence graph",
            "Investigation timeline": "18  Investigation timeline",
            "History": "19  History",
            "Saved reports": "20  Saved reports",
            "Watchlist": "21  Watchlist",
            "Scam alerts": "22  Scam alerts",
            "Analytics": "23  Analytics",
            "Profile": "24  Profile",
            "Settings": "25  Settings",
            "Integrations": "26  Integration status",
            "Risk methodology": "27  Risk methodology",
            "Help & support": "28  Help & support",
            "Admin": "Admin console",
        }[value],
    )
    st.sidebar.markdown("---")
    if user:
        st.sidebar.caption(f"Signed in as {user.get('display_name', user.get('email', 'Account'))}")
        if st.sidebar.button("Sign out", width="stretch"):
            api_call("POST", "/api/auth/logout")
            clear_active_report()
            st.session_state.pop("auth_token", None)
            st.session_state.pop("account", None)
            st.session_state.pop("main_navigation", None)
            st.session_state["show_auth_portal"] = False
            st.rerun()
    healthy, label = service_status()
    label = "API + database online" if healthy else label
    dot_class = "online" if healthy else "offline"
    st.sidebar.markdown(
        f'<div class="service-pill"><span class="status-dot {dot_class}"></span>'
        f'<span>{html.escape(label)}</span></div>',
        unsafe_allow_html=True,
    )
    st.sidebar.caption("TinyFish Search + Fetch · Rule-based analysis")
    st.sidebar.markdown(
        '<div class="sidebar-foot">SCAMSHIELD AI <span>v0.2</span><br>'
        "Evidence-led. Human-reviewed.</div>",
        unsafe_allow_html=True,
    )
    return selected


def render_topbar(title: str, description: str) -> None:
    healthy, _ = service_status()
    service_label = "API HEALTHY" if healthy else "API OFFLINE"
    status_class = "online" if healthy else "offline"
    st.markdown(
        f'<div class="page-heading"><div><div class="eyebrow">SCAMSHIELD / '
        f'{html.escape(title.upper())}</div><h1>{html.escape(title)}</h1>'
        f'<p>{html.escape(description)}</p></div>'
        f'<div class="live-badge"><span class="status-dot {status_class}"></span>'
        f'{service_label}</div></div>',
        unsafe_allow_html=True,
    )


def render_section_title(title: str, subtitle: str | None = None) -> None:
    sub = f"<p>{html.escape(subtitle)}</p>" if subtitle else ""
    st.markdown(
        f'<div class="section-title"><h2>{html.escape(title)}</h2>{sub}</div>',
        unsafe_allow_html=True,
    )


def render_illustration(filename: str, alt: str) -> None:
    allowed_assets = {
        "shield.svg",
        "network.svg",
        "scanner.svg",
        "job-shield.svg",
        "payment-shield.svg",
        "qr-security.svg",
        "evidence-graph.svg",
        "analytics.svg",
        "assistant.svg",
        "message-warning.svg",
        "document-scan.svg",
        "phishing-net.svg",
    }
    if filename not in allowed_assets:
        raise ValueError("Unknown illustration asset.")
    asset_path = APP_ROOT / "frontend" / "assets" / filename
    encoded = base64.b64encode(asset_path.read_bytes()).decode("ascii")
    st.markdown(
        f'<div class="feature-illustration"><img src="data:image/svg+xml;base64,{encoded}" '
        f'alt="{html.escape(alt, quote=True)}" loading="lazy"></div>',
        unsafe_allow_html=True,
    )


def render_metric(label: str, value: str, note: str, icon: str, accent: str) -> None:
    st.markdown(
        f'<div class="metric-card"><div class="metric-top"><span>{html.escape(label)}</span>'
        f'<span class="metric-icon" style="--metric-accent:{accent}">{icon}</span></div>'
        f'<div class="metric-value">{html.escape(value)}</div>'
        f'<div class="metric-note">{html.escape(note)}</div></div>',
        unsafe_allow_html=True,
    )


def render_empty_state(title: str, message: str, action: str | None = None) -> None:
    st.markdown(
        f'<div class="empty-state"><div class="empty-icon">⌁</div>'
        f'<h3>{html.escape(title)}</h3><p>{html.escape(message)}</p></div>',
        unsafe_allow_html=True,
    )
    if action and st.button(action, type="primary"):
        st.session_state["main_navigation"] = "New investigation"
        st.rerun()


def render_risk_gauge(report: dict[str, Any]) -> None:
    score = int(report.get("risk_score", 0))
    category = str(report.get("risk_category", ""))
    color = risk_color(category)
    insufficient_evidence = (
        report.get("risk_assessment_status") == "insufficient_evidence"
    )
    gauge_steps = (
        [{"range": [0, 100], "color": "rgba(102,112,133,.10)"}]
        if insufficient_evidence
        else [
            {"range": [0, 25], "color": "rgba(199,240,0,.24)"},
            {"range": [25, 50], "color": "rgba(169,186,255,.28)"},
            {"range": [50, 75], "color": "rgba(36,87,255,.12)"},
            {"range": [75, 100], "color": "rgba(16,24,40,.08)"},
        ]
    )
    figure = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "<span style='font-size:18px'> / 100</span>", "font": {"size": 46, "color": "#101828"}},
            title={"text": "RISK INDICATOR", "font": {"size": 12, "color": "#667085"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 0, "tickcolor": "rgba(0,0,0,0)", "tickfont": {"color": "#667085"}},
                "bar": {"color": color, "thickness": 0.22},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 0,
                "steps": gauge_steps,
                "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.82, "value": score},
            },
        )
    )
    figure.update_layout(**chart_layout(height=250, margin={"l": 24, "r": 24, "t": 48, "b": 12}))
    st.plotly_chart(
        figure,
        width="stretch",
        config={"displayModeBar": False},
        key=f"risk-gauge-{report.get('id', 'unknown')}",
    )
    st.markdown(
        f'<div class="risk-label" style="--risk-accent:{color}">{html.escape(category)}</div>',
        unsafe_allow_html=True,
    )
    if insufficient_evidence:
        st.caption(
            "The score counts detected warning signals, not proof of safety. "
            "Available evidence does not support a low-risk conclusion."
        )


def render_evidence_card(item: dict[str, Any], index: int) -> None:
    url = str(item.get("url") or "")
    safe_url = html.escape(url, quote=True)
    domain = html.escape(url.split("/")[2] if "://" in url else "Submitted content")
    title = html.escape(str(item.get("title") or item.get("source_type") or "Evidence source"))
    excerpt = html.escape(str(item.get("excerpt") or "No excerpt returned."))
    source_type = html.escape(str(item.get("source_type") or "source").replace("_", " "))
    providers = item.get("providers")
    provider_label = (
        ", ".join(str(value) for value in providers if isinstance(value, str))
        if isinstance(providers, list)
        else str(item.get("provider") or "Provider not recorded")
    )
    provider = html.escape(provider_label)
    relevance = item.get("relevance")
    evidence_status = ""
    if relevance == "unrelated_not_scored":
        evidence_status = '<span class="evidence-status">Unrelated · not scored</span>'
    elif relevance == "redirected_to_other_domain_not_scored":
        evidence_status = '<span class="evidence-status">Different final domain · not scored</span>'
    elif item.get("redirect_detected"):
        evidence_status = '<span class="evidence-status">Redirected · listing details reviewed</span>'
    if url.startswith(("https://", "http://")):
        link = f'<a class="source-link" href="{safe_url}" target="_blank" rel="noopener noreferrer">Open source ↗</a>'
    else:
        link = ""
    st.markdown(
        f'<div class="evidence-card"><div class="evidence-index">{index:02d}</div>'
        f'<div class="evidence-content"><div class="evidence-meta">{source_type} · {provider} '
        f'<span>·</span> {domain} {evidence_status}</div><h4>{title}</h4><p>{excerpt}</p>{link}</div></div>',
        unsafe_allow_html=True,
    )


def clear_active_report() -> None:
    st.session_state.pop("active_report", None)
    st.session_state.pop("active_report_mode", None)


def render_job_verification(report: dict[str, Any]) -> None:
    verification = report.get("job_verification")
    if not isinstance(verification, dict):
        return

    render_section_title(
        "Job & internship verification",
        "Company-level search is not proof of a specific job listing.",
    )

    status_labels = {
        "page_details_match_not_officially_verified": (
            "Partially verified — details match; source not authenticated"
        ),
        "page_details_mismatch": "Mismatch found",
        "page_fetched_details_insufficient": "Partially verified — details incomplete",
        "page_unavailable_or_access_limited": "Unable to verify — page unavailable",
        "fetch_failed": "Unable to verify — Fetch failed",
        "requested_url_not_confirmed": "Unable to verify — requested URL not confirmed",
        "redirected_to_different_domain": "Mismatch found — unrecognized redirect",
        "not_checked_no_offer_url": "Not checked — no offer URL",
        "company_name_found_on_page": "Company name found; ownership unverified",
        "company_name_not_found_on_page": "Mismatch found — company not identified",
        "brand_in_unverified_subdomain": "Warning — brand in unverified subdomain",
        "recognized_third_party_recruitment_platform": (
            "Recognized recruitment platform; employer unverified"
        ),
        "company_name_in_unverified_subdomain": (
            "Company name appears in an unverified subdomain"
        ),
        "employer_domain_unverified": "Employer domain not independently verified",
        "unrecognized_redirect_domain": "Unrecognized redirect domain",
    }

    def display_status(value: Any) -> str:
        status = str(value or "not verified")
        return status_labels.get(status, status.replace("_", " ").capitalize())

    with st.container(border=True):
        statuses = (
            ("Submitted company", verification.get("submitted_company", "not available")),
            ("Company name on fetched page", display_status(verification.get("company_status"))),
            ("Offer URL domain", display_status(verification.get("offer_domain_status"))),
            ("Exact listing", display_status(verification.get("exact_listing_status"))),
            ("Hosting status", display_status(verification.get("hosting_status"))),
            ("Official careers domain", display_status(verification.get("official_careers_domain_status"))),
        )
        for start in range(0, len(statuses), 3):
            status_columns = st.columns(3)
            for column, (label, value) in zip(
                status_columns,
                statuses[start : start + 3],
            ):
                with column:
                    st.markdown(f"**{label}**")
                    st.write(str(value))

        recruiter = verification.get("recruiter")
        if isinstance(recruiter, dict):
            st.markdown("**Recruiter verification**")
            st.write(display_status(recruiter.get("status", "not verified")))
            st.caption(str(recruiter.get("explanation", "")))
            if recruiter.get("email_domain"):
                st.caption(f"Submitted recruiter email domain: {recruiter['email_domain']}")

        if verification.get("recruitment_platform"):
            st.caption(
                f"Recognized third-party recruitment platform: "
                f"{verification['recruitment_platform']}. Platform hosting does not authenticate the employer."
            )

        providers = verification.get("research_providers")
        if isinstance(providers, dict):
            st.caption(
                "Provider attribution: "
                + ", ".join(
                    f"{details.get('provider', name)} ({display_status(details.get('status'))})"
                    for name, details in providers.items()
                    if isinstance(details, dict)
                )
            )

        for label, field in (
            ("Submitted offer URL", "submitted_offer_url"),
            ("Final fetched URL", "final_fetched_url"),
        ):
            value = verification.get(field)
            st.markdown(f"**{label}**")
            if value and str(value).startswith(("https://", "http://")):
                st.link_button(label, str(value))
            else:
                st.caption("Not available")

        if verification.get("page_title"):
            st.markdown(
                f"**Fetched page title:** {html.escape(str(verification['page_title']))}"
            )
        if verification.get("job_title"):
            st.markdown(
                f"**Job title found:** {html.escape(str(verification['job_title']))}"
            )
        if verification.get("job_id"):
            st.markdown(
                f"**Fetched job ID:** `{html.escape(str(verification['job_id']))}`"
            )
        if verification.get("submitted_job_id"):
            st.markdown(
                f"**Submitted job ID:** `{html.escape(str(verification['submitted_job_id']))}`"
            )
        for label, field in (
            ("Company name match", "company_name_match"),
            ("Role details match", "role_details_match"),
            ("Submitted job ID match", "job_id_match"),
        ):
            matched = verification.get(field)
            result = (
                "Not supplied or unavailable"
                if matched is None
                else "Match found" if matched else "No match"
            )
            st.markdown(f"**{label}:** {result}")
        if verification.get("application_details"):
            st.markdown("**Application details found**")
            st.write(str(verification["application_details"]))
        if verification.get("application_url"):
            st.markdown(
                f"**Application URL:** {html.escape(str(verification['application_url']))}"
            )
        if verification.get("available_description"):
            st.markdown("**Fetched job description or page text**")
            st.text(str(verification["available_description"]))
        st.info(str(verification.get("explanation", "Listing authenticity was not independently verified.")))

        positives = report.get("positive_indicators", [])
        if positives:
            st.markdown("**Positive consistency signals**")
            for item in positives:
                adjustment = int(item.get("score_adjustment", 0))
                score_note = (
                    f"(score adjustment: −{adjustment})"
                    if adjustment
                    else "(no score adjustment)"
                )
                st.markdown(
                    f"- **{item.get('name', 'Signal')}** — {item.get('explanation', '')} "
                    f"{score_note}"
                )

        warnings = report.get("indicators", [])
        st.markdown("**Offer condition analysis**")
        if warnings:
            for item in warnings:
                st.markdown(
                    f"- **{item.get('name', 'Warning')}** (+{item.get('score_contribution', 0)}): "
                    f"{item.get('explanation', '')}"
                )
        else:
            st.caption("No configured warning rules matched the submitted details; this is not proof the offer is genuine.")


def render_report(report: dict[str, Any]) -> None:
    if report.get("live_research") == "partial":
        st.warning("Research was incomplete. This is a partial report; do not treat it as a completed live investigation.")
    elif report.get("live_research") == "completed":
        if report.get("investigation_type") == "job":
            st.info("Provider research completed. Review the separate listing and identity statuses; this does not authenticate the offer.")
        else:
            st.success("Live investigation completed with usable evidence.")
    elif report.get("live_research") in {"not_requested", "not_applicable"}:
        st.info("This analysis did not require live research. The result is rule-based.")

    if report.get("investigation_type") == "job":
        render_job_verification(report)
    if report.get("retained_in_history") is False:
        st.caption("This sensitive report is not retained in investigation history.")
    offer_details = report.get("extracted_details")
    if isinstance(offer_details, dict):
        render_section_title(
            "Extracted offer details",
            "Document text/OCR claims are not authenticated facts.",
        )
        st.json(offer_details)
        if report.get("verified_facts"):
            st.markdown("**Verified observations**")
            for fact in report["verified_facts"]:
                st.write(f"- {fact}")
        else:
            st.caption("No offer-letter claim is independently authenticated.")
        if report.get("unverified_claims"):
            st.markdown("**Unverified document claims**")
            for claim in report["unverified_claims"]:
                st.write(f"- {claim}")
    email_details = report.get("email_details")
    if isinstance(email_details, dict):
        render_section_title(
            "Email details",
            "Message content is screened locally unless link research was explicitly requested.",
        )
        st.json(email_details)

    summary, gauge = st.columns([1.3, 0.8], gap="large")
    with summary:
        render_section_title("Investigation summary", str(report.get("target", "Submitted content")))
        st.markdown(
            f'<div class="summary-panel"><div class="summary-tags">'
            f'<span>{html.escape(str(report.get("analysis_method", "rule_based")).replace("_", " ").upper())}</span>'
            f'<span>{html.escape(str(report.get("confidence", "limited")).upper())} CONFIDENCE</span>'
            f'<span>{html.escape(str(report.get("information_completeness", "unknown")))}</span>'
            f'</div><p>{html.escape(str(report.get("scoring_explanation", "")))}</p>'
            f'<small>{html.escape(str(report.get("disclaimer", "")))}</small></div>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"Investigation {report.get('id', '—')} · {report.get('created_at', 'timestamp unavailable')}"
        )
    with gauge:
        with st.container(border=True):
            if report.get("analysis_method") == "evidence_only":
                st.markdown('<div class="risk-label">Risk score not assessed</div>', unsafe_allow_html=True)
                st.caption("Public search evidence only; this report did not analyze risk.")
            else:
                render_risk_gauge(report)

    indicators = report.get("indicators", [])
    groups = [
        ("Verified facts", [item for item in indicators if item.get("classification") == "verified_fact"]),
        ("Public allegations", [item for item in indicators if item.get("classification") == "public_allegation"]),
        ("Rule-based inferences", [item for item in indicators if item.get("classification") == "inference"]),
    ]
    if report.get("analysis_method") == "evidence_only":
        render_section_title("Evidence review", "Public search records only; no score or identity verification.")
    else:
        render_section_title("Signal breakdown", "Each score contribution is tied to a returned source or a transparent rule.")
    if indicators:
        points = [int(item.get("score_contribution", 0)) for item in indicators]
        labels = [str(item.get("name", "Indicator")) for item in indicators]
        colors = [
            "#2457FF" if item.get("classification") == "public_allegation" else "#C7F000"
            for item in indicators
        ]
        figure = go.Figure(go.Bar(
            x=points,
            y=labels,
            orientation="h",
            marker={"color": colors, "line": {"width": 0}, "cornerradius": 6},
            text=[f"+{value}" for value in points],
            textposition="outside",
            hovertemplate="%{y}<br>Score contribution: %{x}<extra></extra>",
        ))
        figure.update_layout(**chart_layout(
            height=max(170, 52 * len(points)),
            xaxis={"visible": False, "range": [0, max(points, default=0) + 15]},
            yaxis={"automargin": True, "gridcolor": "#E5E7EB"},
            showlegend=False,
            margin={"l": 12, "r": 40, "t": 12, "b": 12},
        ))
        st.plotly_chart(
            figure,
            width="stretch",
            config={"displayModeBar": False},
            key=f"risk-breakdown-{report.get('id', 'unknown')}",
        )
        tabs = st.tabs([f"{label} · {len(items)}" for label, items in groups])
        for tab, (label, items) in zip(tabs, groups):
            with tab:
                if not items:
                    st.caption(f"No {label.lower()} were returned.")
                for item in items:
                    with st.container(border=True):
                        st.markdown(
                            f"**{item.get('name', 'Indicator')}**　"
                            f"`+{item.get('score_contribution', 0)}`　"
                            f"`{item.get('severity', 'info')}`"
                        )
                        st.write(item.get("explanation", ""))
                        st.caption(f"Matched evidence: {item.get('evidence', 'No excerpt available.')}")
                        if item.get("source"):
                            st.markdown(f"[View cited source]({item['source']})")
    else:
        if report.get("analysis_method") == "evidence_only":
            st.markdown(
                '<div class="empty-state compact"><h3>No risk assessment was performed</h3>'
                '<p>This report only contains public-source search evidence.</p></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="empty-state compact"><h3>No configured warning patterns matched</h3>'
                '<p>This is not a safety guarantee. Consider the evidence, context and source quality.</p></div>',
                unsafe_allow_html=True,
            )

    evidence = report.get("evidence", [])
    render_section_title("Evidence & intelligence", f"{len(evidence)} source records returned")
    if evidence:
        for index, item in enumerate(evidence, start=1):
            render_evidence_card(item, index)
    else:
        st.caption("No evidence records were returned for this analysis.")

    with st.expander("Investigation timeline"):
        st.markdown(f"**{report.get('created_at', 'Timestamp unavailable')}** · Investigation submitted")
        if report.get("live_research") in {"completed", "partial"}:
            st.markdown(f"**{report.get('created_at', 'Timestamp unavailable')}** · Live research completed · {len(evidence)} evidence items returned")
        for index, item in enumerate(evidence, start=1):
            st.markdown(
                f"**Evidence {index}** · {item.get('source_type', 'source').replace('_', ' ').title()} · "
                f"{item.get('title') or 'Source record'}"
            )
        st.markdown(f"**{report.get('created_at', 'Timestamp unavailable')}** · Analysis and report saved")

    if report.get("analysis_method") != "evidence_only":
        stages = [
            ("Impersonation", ("impersonat", "pretend", "official", "bank", "government", "recruit")),
            ("Urgency", ("urgent", "immediately", "limited time", "act now", "expire", "deadline")),
            ("Fear or pressure", ("threat", "fear", "suspend", "arrest", "penalty", "consequence")),
            ("Requested action", ("pay", "payment", "transfer", "click", "install", "send", "fee")),
            ("Credential or data request", ("otp", "password", "credential", "pin", "verification code", "account details")),
        ]
        indicators_text = " ".join(
            f"{item.get('name', '')} {item.get('explanation', '')} {item.get('evidence', '')}"
            for item in indicators
        ).lower()
        with st.expander("Scam DNA · possible social-engineering sequence"):
            st.caption("A rule-mapped review aid, not a reconstruction of intent. Stages only appear when related evidence or a configured rule is present.")
            for stage, terms in stages:
                matched = any(term in indicators_text for term in terms)
                status = "Indicator present in report" if matched else "No mapped indicator found"
                st.markdown(
                    f'<div class="action-row"><b>{html.escape(stage)}</b> · '
                    f'{html.escape(status)}</div>',
                    unsafe_allow_html=True,
                )

    left, right = st.columns(2, gap="large")
    with left:
        render_section_title("Recommended actions")
        for item in report.get("recommended_next_steps", []):
            st.markdown(f'<div class="action-row"><span>→</span>{html.escape(str(item))}</div>', unsafe_allow_html=True)
    with right:
        render_section_title("Unknown or unverified information")
        missing = report.get("missing_information", [])
        if missing:
            for item in missing:
                st.markdown(f'<div class="gap-row">◇ &nbsp;{html.escape(str(item))}</div>', unsafe_allow_html=True)
        else:
            st.caption("No additional gaps were reported.")

    report_id = str(report.get("id") or "")
    if report_id and report.get("retained_in_history") is False:
        with st.expander("Download this unretained report"):
            st.download_button(
                "Download report data",
                data=json.dumps(report, indent=2, ensure_ascii=False),
                file_name=f"scamshield-{report_id[:8]}.json",
                mime="application/json",
                key=f"json-{report_id}",
            )
    elif report_id:
        with st.expander("Export or share this report"):
            note = st.text_input(
                "Private note for saved report",
                key=f"save-note-{report_id}",
                max_chars=500,
            )
            if st.button("Save to my reports", key=f"save-report-{report_id}"):
                result = api_call(
                    "PUT",
                    f"/api/saved/{quote(report_id, safe='')}",
                    json={"note": note},
                )
                if result is not None:
                    st.success("Report saved to your account.")
            pdf_data = fetch_pdf(report_id)
            if pdf_data is not None:
                st.download_button(
                    "Download PDF report",
                    data=pdf_data,
                    file_name=f"scamshield-{report_id[:8]}.pdf",
                    mime="application/pdf",
                    key=f"pdf-{report_id}",
                )
            st.download_button(
                "Download report data",
                data=json.dumps(report, indent=2, ensure_ascii=False),
                file_name=f"scamshield-{report_id[:8]}.json",
                mime="application/json",
                key=f"json-{report_id}",
            )


def fetch_pdf(report_id: str) -> bytes | None:
    headers = authorization_headers(st.session_state.get("auth_token"))
    try:
        response = httpx.get(
            f"{API_BASE_URL}/api/history/{quote(report_id, safe='')}/pdf",
            timeout=30,
            headers=headers,
        )
    except httpx.RequestError as exc:
        st.error(f"Could not retrieve report PDF ({type(exc).__name__}).")
        return None
    if not response.is_success:
        st.error("Could not retrieve report PDF.")
        return None
    return response.content


def load_report(report_id: str) -> dict[str, Any] | None:
    return api_call("GET", f"/api/history/{quote(report_id, safe='')}")


def render_overview() -> None:
    render_topbar("Security overview", "Evidence-led investigations, risk signals and recent activity.")
    analytics = api_call("GET", "/api/analytics")
    if analytics is None:
        render_empty_state(
            "Your intelligence workspace is waiting",
            "Start the backend to load real investigation metrics and recent records.",
            "Open investigation workspace",
        )
        return

    categories = analytics.get("risk_categories", [])
    scored_categories = [
        item for item in categories if item.get("category") in RISK_COLORS
    ]
    high_count = sum(
        int(item.get("count", 0))
        for item in categories
        if item.get("category") in {"Suspicious", "High risk indicators"}
    )
    latest = analytics.get("latest", [])
    total = int(analytics.get("total_investigations", 0))
    account = st.session_state.get("account", {})
    display_name = str(account.get("display_name") or account.get("email") or "there")
    welcome_detail = (
        f"{total:,} investigation{'s' if total != 1 else ''} in your private workspace."
        if total
        else "Your private workspace is ready. Completed investigations will appear here."
    )
    st.markdown(
        f'<section class="dashboard-welcome">'
        f'<div><div class="eyebrow"><span class="eyebrow-line"></span> SECURITY INTELLIGENCE</div>'
        f'<h2>Welcome back, {html.escape(display_name)}.</h2>'
        f'<p>{html.escape(welcome_detail)} Review evidence and risk signals before you act.</p></div>'
        f'<div class="dashboard-welcome-mark" aria-hidden="true">'
        f'<div class="dashboard-radar"></div><span>SS</span></div>'
        f'</section>',
        unsafe_allow_html=True,
    )
    metric_columns = st.columns(4, gap="medium")
    with metric_columns[0]:
        render_metric("Total investigations", f"{total:,}", "All saved reports", "01", "#2457FF")
    with metric_columns[1]:
        render_metric("Elevated signals", f"{high_count:,}", "Suspicious + high category", "02", "#101828")
    with metric_columns[2]:
        render_metric("Risk classes", f"{len(scored_categories)}/5", "Indicator classes represented", "03", "#C7F000")
    with metric_columns[3]:
        render_metric("Service status", "Online", "FastAPI · SQLite", "04", "#2457FF")

    chart_col, distribution_col = st.columns([1.4, 1], gap="large")
    with chart_col:
        with st.container(border=True):
            render_section_title("Investigation activity", "Daily investigations · recent 30-day window")
            activity = analytics.get("activity", [])
            if activity:
                figure = go.Figure()
                figure.add_trace(go.Scatter(
                    x=[item["date"] for item in activity],
                    y=[item["count"] for item in activity],
                    mode="lines+markers",
                    line={"color": "#4c8dff", "width": 3, "shape": "spline"},
                    marker={"size": 7, "color": "#42e8d1"},
                    fill="tozeroy",
                    fillcolor="rgba(76,141,255,.13)",
                    name="Investigations",
                    hovertemplate="%{x}<br>%{y} investigations<extra></extra>",
                ))
                figure.update_layout(**chart_layout(
                    height=290,
                    xaxis={"showgrid": False, "color": "#9aa9bd"},
                    yaxis={"gridcolor": "rgba(159,178,205,.12)", "color": "#9aa9bd", "rangemode": "tozero"},
                ))
                st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
            else:
                render_empty_state("No activity yet", "Completed investigations will appear here.")
    with distribution_col:
        with st.container(border=True):
            render_section_title("Risk distribution", "Rule-scored reports only; evidence-only lookups are excluded.")
            if scored_categories:
                figure = go.Figure(go.Pie(
                    labels=[item["category"] for item in scored_categories],
                    values=[item["count"] for item in scored_categories],
                    hole=0.72,
                    marker={"colors":[risk_color(item["category"]) for item in scored_categories], "line":{"color":"#111b2b","width":4}},
                    textinfo="none",
                    hovertemplate="%{label}<br>%{value} reports · %{percent}<extra></extra>",
                ))
                figure.add_annotation(
                    text=f"<b>{total}</b><br><span style='font-size:11px'>reports</span>",
                    x=0.5, y=0.5, showarrow=False,
                    font={"size": 24, "color": "#f2f6ff"},
                )
                figure.update_layout(**chart_layout(height=240, showlegend=False))
                st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
                for item in scored_categories:
                    st.markdown(
                        f'<div class="legend-line"><span style="background:{risk_color(item["category"])}"></span>'
                        f'{html.escape(str(item["category"]))}<b>{item["count"]}</b></div>',
                        unsafe_allow_html=True,
                    )
            else:
                render_empty_state("No scored risk reports yet", "Evidence-only public lookup reports are not included in risk charts.")
            unscored_count = sum(
                int(item.get("count", 0))
                for item in categories
                if item.get("category") == "Evidence gathered; not scored"
            )
            if unscored_count:
                st.caption(f"{unscored_count} public intelligence lookup(s) were intentionally not scored.")

    render_section_title("Recent investigations", "Latest real records from the local database.")
    if latest:
        st.dataframe(
            latest,
            width="stretch",
            hide_index=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn(
                    "Risk score", min_value=0, max_value=100, format="%d"
                ),
                "id": st.column_config.TextColumn("Report ID", width="small"),
            },
        )
    else:
        render_empty_state(
            "No investigations recorded",
            "Your completed reports and evidence will appear here. No sample numbers are shown.",
            "Start your first investigation",
        )

    quick_a, quick_b, quick_c, quick_d = st.columns(4)
    quick_actions = [
        (quick_a, "Website", "Investigate a domain"),
        (quick_b, "Offer", "Verify a job offer"),
        (quick_c, "Message", "Analyze suspicious text"),
        (quick_d, "Payment", "Review a payment request"),
    ]
    for column, mode, description in quick_actions:
        with column:
            with st.container(border=True):
                st.markdown(f"**{mode}**")
                st.caption(description)
                if st.button("Open workspace", key=f"quick-{mode}"):
                    st.session_state["investigation_mode"] = mode
                    st.session_state["pending_navigation"] = "New investigation"
                    st.rerun()


def run_investigation(mode: str) -> None:
    report = None
    clear_active_report()
    with st.spinner("Running the selected analysis. Live research can take a short while..."):
        if mode == "Website":
            url = st.session_state.get("website_url", "").strip()
            if not url:
                st.warning("Enter a website URL to continue.")
                return
            report = api_call("POST", "/api/investigations/website", json={"url": url})
        elif mode == "Offer":
            company = st.session_state.get("job_company", "").strip()
            description = st.session_state.get("job_description", "").strip()
            uploaded = st.session_state.get("offer_letter_file")
            if not description and uploaded is None:
                st.warning("Paste offer details or upload an offer letter.")
                return
            data = {
                key: value
                for key, value in {
                    "pasted_text": description,
                    "company_name": company,
                    "recruiter_contact": st.session_state.get("job_contact", "").strip(),
                    "job_title": st.session_state.get("offer_job_title", "").strip(),
                    "job_id": st.session_state.get("offer_job_id", "").strip(),
                    "salary_or_stipend": st.session_state.get("offer_salary", "").strip(),
                    "offer_date": st.session_state.get("offer_date", "").strip(),
                    "joining_date": st.session_state.get("joining_date", "").strip(),
                    "offer_url": st.session_state.get("job_url", "").strip(),
                    "application_url": st.session_state.get("application_url", "").strip(),
                }.items()
                if value
            }
            data["retain_report"] = str(
                st.session_state.get("retain_offer_report", False)
            ).lower()
            files = None
            if uploaded is not None:
                files = {
                    "file": (
                        uploaded.name,
                        uploaded.getvalue(),
                        uploaded.type or "application/octet-stream",
                    )
                }
            report = api_call(
                "POST",
                "/api/investigations/offer-letter",
                data=data,
                files=files,
            )
        elif mode == "Email Scam Analysis":
            body_text = st.session_state.get("email_body", "").strip()
            uploaded = st.session_state.get("email_file")
            if not body_text and uploaded is None:
                st.warning("Paste an email or upload a plain-text .eml file.")
                return
            if uploaded is not None:
                report = api_call(
                    "POST",
                    "/api/analyze/email-upload",
                    data={
                        "retain_report": str(
                            st.session_state.get("retain_email_report", False)
                        ).lower()
                    },
                    files={
                        "file": (
                            uploaded.name,
                            uploaded.getvalue(),
                            uploaded.type or "message/rfc822",
                        )
                    },
                )
            else:
                report = api_call(
                    "POST",
                    "/api/analyze/email",
                    json={
                        "sender": st.session_state.get("email_sender", "").strip() or None,
                        "subject": st.session_state.get("email_subject", "").strip() or None,
                        "body": body_text,
                        "research_links": st.session_state.get("email_research_links", False),
                        "retain_report": st.session_state.get("retain_email_report", False),
                    },
                )
        elif mode in {"Email Intelligence", "Phone Intelligence", "Company Intelligence", "Domain Intelligence"}:
            entity = st.session_state.get("entity_value", "").strip()
            if not entity:
                st.warning("Enter an entity to investigate.")
                return
            entity_type = mode.split(" ", 1)[0].lower()
            body = {
                "entity_type": entity_type,
                "value": entity,
                "consent_to_public_search": st.session_state.get("public_search_consent", False),
            }
            report = api_call("POST", "/api/investigations/intelligence", json=body)
        elif mode in {"Message", "Payment"}:
            text = st.session_state.get("text_input", "").strip()
            if not text:
                st.warning("Enter the message or payment request.")
                return
            if mode == "Message":
                body = {"text": text, "research_links": st.session_state.get("research_links", False)}
                route = "/api/analyze/message"
            else:
                body = {"text": text}
                merchant = st.session_state.get("merchant_name", "").strip()
                if merchant:
                    body["merchant_name"] = merchant
                route = "/api/analyze/payment"
            report = api_call("POST", route, json=body)
    if report:
        st.session_state["active_report"] = report
        st.session_state["active_report_mode"] = mode


def render_investigation_workspace() -> None:
    render_topbar("Investigation workspace", "Choose a target. Review the evidence. Keep the final decision human.")
    mode = st.selectbox(
        "Investigation type",
        [
            "Website", "Offer", "Message", "Payment",
            "Email Scam Analysis", "Email Intelligence", "Phone Intelligence",
            "Company Intelligence", "Domain Intelligence",
        ],
        key="investigation_mode",
        on_change=clear_active_report,
        format_func={
            "Website": "Website intelligence",
            "Offer": "Job & internship verification",
            "Email Scam Analysis": "Email scam and phishing analysis",
            "Message": "Suspicious message analysis",
            "Payment": "Payment request analysis",
            "Email Intelligence": "Email public-source lookup · authorized use only",
            "Phone Intelligence": "Phone public-source lookup · authorized use only",
            "Company Intelligence": "Company public-source lookup",
            "Domain Intelligence": "Domain public-source lookup",
        }.get,
    )
    if (
        st.session_state.get("active_report")
        and st.session_state.get("active_report_mode") not in {None, mode}
    ):
        clear_active_report()
    help_text = {
        "Website": "Research a public site with TinyFish Search and inspect page content with TinyFish Fetch.",
        "Offer": "Search for job-specific public evidence and fetch the exact offer URL when supplied. Company search alone does not verify a listing.",
        "Email Scam Analysis": "Analyze pasted email content or a plain-text .eml file. Attachments are ignored and links are only researched after opt-in.",
        "Message": "Run transparent local rules. Link lookups require explicit opt-in.",
        "Payment": "Screen the request text and optionally search for merchant information.",
        "Email Intelligence": "Search for public sources associated with the submitted email. This does not verify ownership or identity.",
        "Phone Intelligence": "Search for public sources associated with the submitted number. This does not verify ownership or identity.",
        "Company Intelligence": "Collect public search results for a company name. Results can refer to unrelated entities.",
        "Domain Intelligence": "Collect public search results for a domain. Use the URL scanner for page fetching.",
    }
    st.markdown(
        f'<div class="workspace-intro"><span class="workspace-kicker">TARGET ANALYSIS</span>'
        f'<p>{html.escape(help_text[mode])}</p></div>',
        unsafe_allow_html=True,
    )
    with st.container(border=True):
        if mode == "Website":
            st.text_input("Website URL", placeholder="https://company.example", key="website_url")
            st.caption("Only submit public HTTP(S) pages you are authorized to investigate.")
        elif mode == "Offer":
            st.text_input("Company or organization", placeholder="Company name", key="job_company")
            st.file_uploader(
                "Offer letter · PDF, JPG, JPEG, or PNG",
                type=["pdf", "jpg", "jpeg", "png"],
                key="offer_letter_file",
                max_upload_size=8,
                help="Files are processed in memory and are not retained by the server.",
            )
            st.text_area(
                "Job, internship or offer details",
                placeholder="Paste offer text, or add context that could not be extracted from the uploaded file.",
                height=150,
                key="job_description",
            )
            fields = st.columns(2)
            with fields[0]:
                st.text_input("Recruiter contact · optional", key="job_contact")
                st.text_input("Job title or internship role · optional", key="offer_job_title")
                st.text_input("Job ID · optional", key="offer_job_id")
                st.text_input("Salary or stipend · optional", key="offer_salary")
                st.text_input("Offer date · optional", key="offer_date")
            with fields[1]:
                st.text_input("Joining date · optional", key="joining_date")
                st.text_input("Exact offer/listing URL · optional", placeholder="https://", key="job_url")
                st.text_input("Application URL · optional", placeholder="https://", key="application_url")
                st.checkbox(
                    "Retain the redacted report in my private history",
                    key="retain_offer_report",
                    help="The uploaded file and full extracted text are never retained.",
                )
            st.caption("Exact supplied URLs are fetched through TinyFish. Company search results alone do not verify a listing.")
        elif mode == "Email Scam Analysis":
            st.text_input("Sender address · optional", key="email_sender")
            st.text_input("Subject · optional", key="email_subject")
            st.file_uploader(
                "Email file · plain-text .eml only",
                type=["eml"],
                key="email_file",
                max_upload_size=8,
                help="Attachments are ignored and never opened.",
            )
            st.text_area(
                "Email content",
                placeholder="Paste the message body, including suspicious links if present.",
                height=170,
                key="email_body",
            )
            st.checkbox(
                "I authorize live public research for links in this email",
                key="email_research_links",
                help="Up to three URLs are sent for live research only when explicitly selected.",
            )
            st.checkbox(
                "Retain the redacted email report in my private history",
                key="retain_email_report",
                help="The complete email body and uploaded file are never retained.",
            )
            st.caption("Email links are not opened automatically. Sender identity and email authentication remain unverified.")
        elif mode in {"Message", "Payment"}:
            st.text_area(
                "Message or payment request",
                placeholder="Paste suspicious content to analyze. Submitted content is not stored verbatim.",
                height=170,
                key="text_input",
            )
            if mode == "Message":
                st.checkbox(
                    "I authorize live Search and Fetch for links in this message",
                    key="research_links",
                    help="Only after you opt in, up to three HTTP(S) links will be looked up.",
                )
            else:
                st.text_input("Merchant name · optional", key="merchant_name")
                st.caption("Payment IDs are not independently validated; a warning score does not establish fraud.")
        else:
            st.text_input(
                f"{mode.split(' ', 1)[0]} or organization",
                key="entity_value",
                max_chars=300,
            )
            if mode in {"Email Intelligence", "Phone Intelligence"}:
                st.checkbox(
                    "I am authorized to submit this email/phone value to a public search provider.",
                    key="public_search_consent",
                )
                st.warning("The value will be sent to TinyFish Search. Do not submit private, confidential or sensitive identifiers.")
            st.caption("This tool gathers public search results only. It does not independently verify identity, ownership, or reputation.")
        if st.button("Run investigation", type="primary", width="content"):
            run_investigation(mode)

    if st.session_state.get("active_report"):
        st.markdown("---")
        render_report(st.session_state["active_report"])


def render_threat_intelligence() -> None:
    render_topbar("Threat intelligence", "Explore source-backed intelligence from completed investigations.")
    records = api_call("GET", "/api/history?limit=100")
    if records is None:
        return
    if not records:
        render_empty_state(
            "No intelligence records yet",
            "Evidence appears here after an investigation returns sources.",
            "Investigate a target",
        )
        return
    eligible = [row for row in records if row.get("investigation_type") in {"website", "job"}]
    if not eligible:
        render_empty_state("No web evidence yet", "Run a website or job investigation to collect live source records.")
        return
    labels = {
        row["id"]: f'{row["created_at"][:10]} · {row["investigation_type"].title()} · {row["target"][:70]}'
        for row in eligible
    }
    selected = st.selectbox("Select investigation", list(labels), format_func=labels.get)
    if selected:
        report = load_report(selected)
        if report:
            st.markdown(
                f'<div class="intel-banner"><div><span class="eyebrow">SOURCE RECORD</span>'
                f'<h2>{html.escape(str(report.get("target", "")))}</h2></div>'
                f'<span class="intel-date">{html.escape(str(report.get("created_at", "")))}</span></div>',
                unsafe_allow_html=True,
            )
            if report.get("live_research") != "completed":
                st.warning("This investigation contains partial live research.")
            if report.get("sources"):
                st.markdown("#### Search and fetch sources")
                for index, item in enumerate(report.get("evidence", []), 1):
                    render_evidence_card(item, index)
            if report.get("indicators"):
                st.markdown("#### Rule matches and source-supported signals")
                for item in report["indicators"]:
                    st.markdown(
                        f'<div class="action-row"><b>{html.escape(str(item.get("classification", "signal")).replace("_", " ").title())}</b>'
                        f'&nbsp; · &nbsp;{html.escape(str(item.get("name", "")))}'
                        f'&nbsp; · &nbsp;+{item.get("score_contribution", 0)}'
                        f'<br><small>{html.escape(str(item.get("explanation", "")))}</small></div>',
                        unsafe_allow_html=True,
                    )


def render_history() -> None:
    render_topbar("Investigation history", "Search, filter, compare, export or remove your saved investigations.")
    filter_cols = st.columns([1.5, 1, 1.4, 0.8], gap="medium")
    with filter_cols[0]:
        search_text = st.text_input("Search targets", placeholder="Domain or company")
    with filter_cols[1]:
        type_filter = st.selectbox(
            "Type",
            ["All", "website", "job", "message", "payment", "email", "phone", "company", "domain"],
        )
    with filter_cols[2]:
        risk_filter = st.selectbox(
            "Risk category",
            ["All", *RISK_COLORS.keys()],
        )
    with filter_cols[3]:
        limit = st.selectbox("Rows", [25, 50, 100, 200], index=1)
    params: dict[str, Any] = {"limit": limit}
    if type_filter != "All":
        params["investigation_type"] = type_filter
    if risk_filter != "All":
        params["risk_category"] = risk_filter
    if search_text.strip():
        params["search_text"] = search_text.strip()
    records = api_call("GET", "/api/history", params=params)
    if records is None:
        return
    if not records:
        render_empty_state("No matching investigations", "Try changing the filters or run a new investigation.")
        return

    csv_buffer = io.StringIO()
    fields = list(records[0].keys())
    writer = csv.DictWriter(csv_buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)
    st.download_button(
        "Export visible history as CSV",
        data=csv_buffer.getvalue(),
        file_name="scamshield-history.csv",
        mime="text/csv",
    )

    st.dataframe(
        records,
        width="stretch",
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%d"),
        },
    )
    record_ids = [record["id"] for record in records]
    format_labels = {row["id"]: f'{row["investigation_type"].title()} · {row["target"][:60]}' for row in records}
    selected_id = st.selectbox("Open a saved report", record_ids, format_func=format_labels.get)
    if selected_id:
        report = load_report(selected_id)
        if report:
            render_report(report)
            with st.expander("Delete this investigation"):
                confirmed = st.checkbox(
                    "I understand this permanently deletes the report and its saved bookmark.",
                    key=f"confirm-delete-{selected_id}",
                )
                if st.button("Delete investigation", disabled=not confirmed, key=f"delete-{selected_id}"):
                    deleted = api_call(
                        "DELETE",
                        f"/api/history/{quote(selected_id, safe='')}",
                    )
                    if deleted is not None:
                        st.session_state.pop("active_report", None)
                        st.success("Investigation deleted.")
                        st.rerun()

    st.markdown("---")
    render_section_title("Compare two reports", "Side-by-side comparison uses saved report values only.")
    if len(record_ids) >= 2:
        first_col, second_col = st.columns(2)
        with first_col:
            first_id = st.selectbox("First report", record_ids, format_func=format_labels.get, key="compare_first")
        with second_col:
            second_id = st.selectbox(
                "Second report",
                [item for item in record_ids if item != first_id],
                format_func=format_labels.get,
                key="compare_second",
            )
        if st.button("Compare reports"):
            first_report = load_report(first_id)
            second_report = load_report(second_id)
            if first_report and second_report:
                left, right = st.columns(2)
                for column, report in ((left, first_report), (right, second_report)):
                    with column:
                        with st.container(border=True):
                            st.markdown(f"**{report['target']}**")
                            st.metric("Risk score", f"{report['risk_score']}/100")
                            st.caption(report["risk_category"])
                            st.write(f"{len(report.get('evidence', []))} evidence records")
                            st.write(f"{len(report.get('indicators', []))} indicators")
    else:
        st.caption("Two saved reports are needed to compare.")


def render_saved_reports() -> None:
    render_topbar("Saved reports", "Private report bookmarks stored in your account.")
    records = api_call("GET", "/api/saved")
    if records is None:
        return
    if not records:
        render_empty_state("No saved reports", "Save an investigation report to find it here.")
        return
    st.dataframe(
        records,
        width="stretch",
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%d"),
        },
    )
    labels = {
        row["id"]: f'{row["investigation_type"].title()} · {row["target"][:60]}'
        for row in records
    }
    selected = st.selectbox("Open a saved report", list(labels), format_func=labels.get)
    if selected:
        report = load_report(selected)
        if report:
            render_report(report)
            if st.button("Remove from saved reports", key=f"unsave-{selected}"):
                removed = api_call("DELETE", f"/api/saved/{quote(selected, safe='')}")
                if removed is not None:
                    st.rerun()


def render_watchlist() -> None:
    render_topbar("Watchlist", "Opt in to scheduled public checks for domains and organizations.")
    status = api_call("GET", "/api/monitoring/status")
    if status is not None:
        if status.get("scheduler_running"):
            st.success(f"Background monitoring is running · {status.get('scheduled_jobs', 0)} scheduled check(s).")
        else:
            st.warning("The scheduler is not running. Monitoring cannot be enabled in this process.")
    with st.form("watchlist-add"):
        col_value, col_kind = st.columns([2, 1])
        with col_value:
            value = st.text_input("Domain, email, phone or organization", max_chars=500)
        with col_kind:
            item_type = st.selectbox(
                "Entry type",
                ["domain", "email", "phone", "organization"],
                format_func=str.title,
            )
        submitted = st.form_submit_button("Add to watchlist", type="primary")
    if submitted:
        added = api_call(
            "POST",
            "/api/watchlist",
            json={"value": value, "item_type": item_type},
        )
        if added is not None:
            st.success("Added to your watchlist.")
            st.rerun()
    entries = api_call("GET", "/api/watchlist")
    if entries is None:
        return
    if not entries:
        render_empty_state("Your watchlist is empty", "Add a domain or organization for optional monitoring.")
        return
    for entry in entries:
        with st.container(border=True):
            st.markdown(f"**{html.escape(entry['value'])}** · {html.escape(entry['item_type'].title())}")
            st.caption(f"Added {html.escape(entry['created_at'])}")
            if entry["item_type"] in {"domain", "organization"}:
                settings = api_call(
                    "GET",
                    f"/api/watchlist/{quote(entry['id'], safe='')}/monitoring",
                )
                if settings is not None:
                    enabled = st.checkbox(
                        "Enable scheduled monitoring",
                        value=bool(settings.get("enabled")),
                        key=f"monitor-enabled-{entry['id']}",
                    )
                    intervals = [6, 12, 24, 168]
                    selected_interval = st.selectbox(
                        "Check interval",
                        intervals,
                        index=intervals.index(settings.get("interval_hours", 24))
                        if settings.get("interval_hours", 24) in intervals
                        else 2,
                        format_func=lambda hours: f"Every {hours} hours"
                        if hours < 168
                        else "Weekly",
                        key=f"monitor-interval-{entry['id']}",
                        disabled=not enabled,
                    )
                    if st.button("Save monitoring settings", key=f"save-monitor-{entry['id']}"):
                        updated = api_call(
                            "PUT",
                            f"/api/watchlist/{quote(entry['id'], safe='')}/monitoring",
                            json={
                                "enabled": enabled,
                                "interval_hours": selected_interval,
                            },
                        )
                        if updated is not None:
                            st.success(
                                "Monitoring schedule saved."
                                if updated.get("job_scheduled")
                                else "Monitoring paused."
                            )
                            st.rerun()
                    if settings.get("enabled") and settings.get("job_scheduled"):
                        st.caption(f"Next scheduled check: {settings.get('next_run_time', 'scheduled')}")
                    if st.button("Check now", key=f"check-watch-{entry['id']}"):
                        checked = api_call(
                            "POST",
                            f"/api/watchlist/{quote(entry['id'], safe='')}/check",
                        )
                        if checked is not None:
                            if checked.get("status") == "completed":
                                st.success("Manual check completed.")
                                st.json(checked.get("changes", {}))
                            else:
                                st.warning("The check could not be completed; no verification is claimed.")
                    checks = api_call(
                        "GET",
                        f"/api/watchlist/{quote(entry['id'], safe='')}/checks",
                        params={"limit": 5},
                    )
                    if checks:
                        with st.expander("Recent monitoring checks"):
                            for check in checks:
                                st.markdown(
                                    f"**{check['checked_at']}** · {check['status']}"
                                )
                                if check.get("changes"):
                                    st.json(check["changes"])
            else:
                st.caption("This entry is saved for manual follow-up; scheduled checks support domains and organizations.")
            if st.button("Remove", key=f"remove-watch-{entry['id']}"):
                deleted = api_call("DELETE", f"/api/watchlist/{quote(entry['id'], safe='')}")
                if deleted is not None:
                    st.rerun()


def render_monitoring_alerts() -> None:
    render_topbar("Monitoring alerts", "Private in-app alerts created by scheduled watchlist checks.")
    alerts = api_call("GET", "/api/monitoring/alerts")
    if alerts is None:
        return
    if not alerts:
        render_empty_state("No monitoring alerts", "Alerts appear when an opted-in check detects a meaningful change.")
        return
    for alert in alerts:
        with st.container(border=True):
            st.markdown(f"**{html.escape(alert['value'])}**")
            st.write(alert["message"])
            st.caption(f"Detected {alert['created_at']} · {'Read' if alert['read_at'] else 'Unread'}")
            if not alert["read_at"] and st.button("Mark as read", key=f"read-alert-{alert['id']}"):
                marked = api_call(
                    "POST",
                    f"/api/monitoring/alerts/{quote(alert['id'], safe='')}/read",
                )
                if marked is not None:
                    st.rerun()


def render_batch_investigation() -> None:
    render_topbar("Batch URL investigation", "Each URL is investigated independently; failed entries do not stop the rest.")
    st.caption("Submit at most 10 URLs. Duplicate canonical URLs are only processed once.")
    urls_text = st.text_area(
        "URLs · one per line",
        key="batch_urls",
        height=150,
        placeholder="https://example.com\nhttps://careers.example.org/jobs/123",
    )
    csv_file = st.file_uploader(
        "Or upload a CSV with a URL column",
        type=["csv"],
        key="batch_csv",
        max_upload_size=1,
    )
    if st.button("Investigate batch", type="primary"):
        urls = [line.strip() for line in urls_text.splitlines() if line.strip()]
        if csv_file is not None:
            raw_csv = csv_file.getvalue()
            if len(raw_csv) > 1024 * 1024:
                st.error("CSV files must be 1 MB or smaller.")
                return
            try:
                rows = list(csv.reader(io.StringIO(raw_csv.decode("utf-8-sig"))))
            except (UnicodeDecodeError, csv.Error):
                st.error("The CSV must be valid UTF-8 text.")
                return
            if rows:
                header = [value.strip().casefold() for value in rows[0]]
                url_column = header.index("url") if "url" in header else 0
                start = 1 if "url" in header else 0
                for row in rows[start:]:
                    if len(row) > url_column and row[url_column].strip():
                        urls.append(row[url_column].strip())
        if not urls:
            st.warning("Enter or upload at least one URL.")
        elif len(urls) > 10:
            st.error("Batch size is limited to 10 unique URL inputs.")
        else:
            result = api_call(
                "POST",
                "/api/investigations/batch",
                json={"urls": urls},
                timeout=360,
            )
            if result is not None:
                st.session_state["batch_result"] = result

    result = st.session_state.get("batch_result")
    if not result:
        return
    st.markdown("#### Batch summary")
    st.json(result["summary"])
    export = io.StringIO()
    writer = csv.writer(export)
    writer.writerow(["submitted_url", "status", "risk_score", "risk_category", "error"])
    for item in result["results"]:
        report = item.get("report", {})
        writer.writerow(
            [
                item.get("submitted_url", ""),
                item.get("status", ""),
                report.get("risk_score", ""),
                report.get("risk_category", ""),
                item.get("error", ""),
            ]
        )
    st.download_button(
        "Download batch CSV",
        export.getvalue(),
        file_name="scamshield-batch-results.csv",
        mime="text/csv",
    )
    for item in result["results"]:
        label = f"{item.get('status', 'unknown').title()} · {item.get('submitted_url', 'URL')}"
        with st.expander(label):
            if item.get("status") == "completed":
                render_report(item["report"])
            elif item.get("status") == "duplicate":
                st.info(f"Duplicate of {item.get('duplicate_of', 'another submitted URL')}.")
            else:
                st.error(item.get("error", "This URL could not be investigated."))


def render_screenshot_analyzer() -> None:
    render_topbar("Screenshot / OCR analysis", "Extract text locally, then screen it with existing rules.")
    upload = st.file_uploader(
        "Screenshot · JPG, JPEG, or PNG",
        type=["jpg", "jpeg", "png"],
        key="screenshot_file",
        max_upload_size=8,
    )
    if upload is not None:
        image_bytes = upload.getvalue()
        st.image(image_bytes, caption="Original screenshot", width="stretch")
        context = st.selectbox(
            "Analyze as",
            ["message", "job", "payment"],
            format_func=str.title,
            key="screenshot_context",
        )
        retain = st.checkbox(
            "Retain the redacted report in my private history",
            key="retain_screenshot_report",
        )
        if st.button("Extract and analyze screenshot", type="primary"):
            report = api_call(
                "POST",
                "/api/analyze/screenshot",
                files={"file": (upload.name, image_bytes, upload.type or "image/png")},
                data={"context": context, "retain_report": str(retain).lower()},
            )
            if report is not None:
                st.session_state["active_report"] = report
                st.session_state["active_report_mode"] = "Screenshot"
    report = st.session_state.get("active_report")
    if report and report.get("investigation_type") == "screenshot":
        if report.get("ocr_confidence") is not None:
            st.metric("OCR mean word confidence", f"{report['ocr_confidence']}/100")
            st.caption(report.get("confidence_method", "This is not a probability of correctness."))
        with st.expander("Extracted text · verify against the original image"):
            st.text(report.get("extracted_text", ""))
        render_report(report)


def render_qr_scanner() -> None:
    render_topbar("QR code scanner", "Decode first. Inspect the destination before choosing any investigation.")
    upload = st.file_uploader(
        "QR image · JPG, JPEG, or PNG",
        type=["jpg", "jpeg", "png"],
        key="qr_file",
        max_upload_size=8,
    )
    if upload is not None:
        image_bytes = upload.getvalue()
        st.image(image_bytes, caption="Original QR image", width="stretch")
        if st.button("Decode QR code", type="primary"):
            report = api_call(
                "POST",
                "/api/analyze/qr",
                files={"file": (upload.name, image_bytes, upload.type or "image/png")},
            )
            if report is not None:
                st.session_state["qr_scan_report"] = report
    report = st.session_state.get("qr_scan_report")
    if not report:
        return
    st.markdown("#### Decoded content · not opened")
    st.code(report.get("decoded_content", ""), language=None)
    st.metric("Rule-based screening score", f"{report.get('risk_score', 0)}/100")
    st.caption(report.get("risk_category", "Unable to assess"))
    if report.get("indicators"):
        for indicator in report["indicators"]:
            st.warning(
                f"{indicator.get('name')}: {indicator.get('explanation')} "
                f"(+{indicator.get('score_contribution', 0)})"
            )
    for index, url in enumerate(report.get("decoded_urls", [])):
        st.code(url, language=None)
        if st.button("Prepare an explicit website investigation", key=f"qr-investigate-{index}"):
            st.session_state["website_url"] = url
            st.session_state["investigation_mode"] = "Website"
            st.session_state["pending_navigation"] = "URL scanner"
            st.rerun()
    st.info("No QR destination is opened or fetched automatically. The website scanner will apply public-URL validation.")
    if report.get("missing_information"):
        st.caption("Limitations: " + " ".join(report["missing_information"]))


def render_ai_assistant() -> None:
    render_topbar("Optional AI analysis", "Gemini provides supplementary interpretations; it never changes the rule-based score.")
    records = api_call("GET", "/api/history", params={"limit": 100})
    if records is None:
        return
    option = st.radio(
        "Analysis input",
        ["Existing report", "Text"],
        horizontal=True,
        key="ai_input_mode",
    )
    request: dict[str, str] = {}
    if option == "Existing report":
        if not records:
            st.info("No saved investigations are available yet. Run an investigation first.")
            return
        labels = {
            row["id"]: f'{row["investigation_type"].title()} · {row["target"][:70]}'
            for row in records
        }
        selected_id = st.selectbox(
            "Select a report",
            list(labels),
            format_func=labels.get,
            key="ai_report_id",
        )
        request["investigation_id"] = selected_id
    else:
        text = st.text_area(
            "Text to interpret",
            key="ai_text",
            max_chars=10000,
            height=180,
        )
        if text.strip():
            request["text"] = text.strip()
    consent = st.checkbox(
        "I authorize sending the selected report/text to the configured Gemini provider",
        key="ai_external_consent",
    )
    if st.button("Request AI interpretation", type="primary", disabled=not consent or not request):
        result = api_call("POST", "/api/analyze/ai", json=request)
        if result is not None:
            st.session_state["ai_result"] = result
    result = st.session_state.get("ai_result")
    if result:
        st.warning(result["label"])
        st.markdown("**Assessment**")
        st.write(result["assessment"])
        if result.get("interpretations"):
            st.markdown("**AI-generated interpretations**")
            for item in result["interpretations"]:
                st.write(f"- {item}")
        if result.get("unknowns"):
            st.markdown("**Unknowns**")
            for item in result["unknowns"]:
                st.write(f"- {item}")
        st.caption(
            f"Original score: {result.get('original_risk_score')} · "
            f"{result.get('original_risk_category')} · unchanged"
        )
        if result.get("cited_evidence"):
            st.markdown("**Supplied evidence cited by the model**")
            for item in result["cited_evidence"]:
                render_evidence_card(item, int(item.get("index", 0)) + 1)
        for limitation in result.get("limitations", []):
            st.caption(limitation)


def render_integrations() -> None:
    render_topbar("Integrations", "Service configuration status without exposing credentials.")
    data = api_call("GET", "/api/integrations")
    if data is None:
        return
    names = {
        "tinyfish_search": "TinyFish Search",
        "tinyfish_fetch": "TinyFish Fetch",
        "gemini": "Gemini analysis",
        "virustotal": "VirusTotal",
        "ocr": "Image OCR",
        "qr_scanning": "QR scanning",
        "watchlist_monitoring": "Watchlist scheduler",
        "speech_to_text": "Speech-to-text",
    }
    for key, label in names.items():
        service = data.get(key, {})
        configured = bool(service.get("configured"))
        with st.container(border=True):
            status = str(service.get("status", "unknown")).replace("_", " ")
            state = "Available" if configured else status.title()
            dot_class = "online" if configured else "offline"
            st.markdown(
                f'<span class="status-dot {dot_class}"></span>&nbsp;'
                f'**{html.escape(label)}** · {html.escape(state)}',
                unsafe_allow_html=True,
            )
            if key.startswith("tinyfish_") and configured:
                st.caption("Configuration is present. This status does not perform a live health request.")
            elif service.get("status") == "optional_provider_not_configured":
                st.caption("Optional provider is not configured. Rule-based analysis remains available.")
            elif service.get("status") == "not_implemented":
                st.caption("This capability is not implemented.")


def render_account() -> None:
    user = st.session_state.get("account", {})
    render_topbar("Account settings", "Manage your local account and credentials.")
    with st.container(border=True):
        st.markdown(f"**Email:** {html.escape(user.get('email', ''))}")
        st.markdown(f"**Role:** {html.escape(user.get('role', 'user').title())}")
        with st.form("profile-form"):
            display_name = st.text_input("Display name", value=user.get("display_name", ""), max_chars=80)
            profile_submitted = st.form_submit_button("Update profile")
        if profile_submitted:
            updated = api_call("PATCH", "/api/auth/profile", json={"display_name": display_name})
            if updated is not None:
                st.session_state["account"] = updated
                st.success("Profile updated.")
    with st.expander("Change password"):
        with st.form("password-form"):
            current_password = st.text_input("Current password", type="password")
            new_password = st.text_input("New password (at least 12 characters)", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            password_submitted = st.form_submit_button("Change password")
        if password_submitted:
            if new_password != confirm_password:
                st.error("The new password entries do not match.")
            else:
                changed = api_call(
                    "POST",
                    "/api/auth/password",
                    json={"current_password": current_password, "new_password": new_password},
                )
                if changed is not None:
                    st.session_state.pop("auth_token", None)
                    st.session_state.pop("account", None)
                    st.session_state.pop("main_navigation", None)
                    st.session_state["show_auth_portal"] = True
                    st.session_state["auth_mode"] = "Sign in"
                    st.session_state["auth_notice"] = "Password updated. Sign in with your new password."
                    st.rerun()
    with st.expander("Delete account and owned data"):
        st.warning("This permanently removes your account, investigations, saved reports and watchlist entries. Existing unowned legacy records are retained.")
        confirmed = st.checkbox("I understand this action cannot be undone.", key="confirm-account-delete")
        if st.button("Delete my account", disabled=not confirmed):
            deleted = api_call("DELETE", "/api/auth/account")
            if deleted is not None:
                st.session_state.clear()
                st.success("Account and owned data deleted.")
                st.rerun()


def render_admin() -> None:
    render_topbar("Administration", "Restricted server-side administrator metrics.")
    data = api_call("GET", "/api/admin/analytics")
    if data is None:
        return
    cols = st.columns(3)
    for col, key, label in zip(
        cols,
        ("registered_users", "investigations", "active_sessions"),
        ("Registered accounts", "Investigations", "Active sessions"),
    ):
        with col:
            render_metric(label, str(data[key]), "Current database count", "◇", "#2457FF")


def select_investigation_for_view(title: str) -> dict[str, Any] | None:
    report = st.session_state.get("active_report")
    if report:
        return report
    records = api_call("GET", "/api/history", params={"limit": 100})
    if records is None:
        return None
    if not records:
        render_empty_state(title, "Complete an investigation to populate this view.")
        return None
    labels = {
        row["id"]: f'{row["created_at"][:10]} · {row["investigation_type"].title()} · {row["target"][:55]}'
        for row in records
    }
    selected_id = st.selectbox("Select investigation", list(labels), format_func=labels.get)
    return load_report(selected_id) if selected_id else None


def render_evidence_graph() -> None:
    render_topbar("Evidence relationship graph", "Connections show which public sources were returned with an investigation—not verified ownership or identity.")
    report = select_investigation_for_view("No evidence graph")
    if not report:
        return
    sources = [
        item for item in report.get("evidence", [])
        if isinstance(item, dict) and isinstance(item.get("url"), str)
        and urlsplit(str(item["url"])).scheme in {"http", "https"}
    ]
    if not sources:
        render_empty_state("No source links to graph", "This investigation did not return linkable evidence records.")
        return
    labels = [str(report.get("target", "Investigation"))[:42]]
    for index, source in enumerate(sources, start=1):
        parsed = urlsplit(str(source["url"]))
        labels.append(f"{parsed.hostname or 'Source'} · {index}")
    count = len(labels)
    x_values = [0.5] + [index / (len(sources) + 1) for index in range(1, len(sources) + 1)]
    y_values = [0.5] + [0.5 + 0.25 * (1 if index % 2 else -1) for index in range(1, count)]
    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for index in range(1, count):
        edge_x.extend([x_values[0], x_values[index], None])
        edge_y.extend([y_values[0], y_values[index], None])
    figure = go.Figure()
    figure.add_trace(go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line={"color": "rgba(36,87,255,.38)", "width": 2},
        hoverinfo="skip",
        showlegend=False,
    ))
    figure.add_trace(go.Scatter(
        x=x_values,
        y=y_values,
        mode="markers+text",
        text=labels,
        textposition=["middle center"] + ["bottom center" if i % 2 else "top center" for i in range(1, count)],
        marker={
            "size": [32] + [20] * len(sources),
            "color": ["#2457FF"] + ["#C7F000"] * len(sources),
            "line": {"color": "#FFFFFF", "width": 1},
        },
        hovertemplate="%{text}<extra>Evidence grouped under this report</extra>",
        showlegend=False,
    ))
    figure.update_layout(
        **chart_layout(
            height=390,
            xaxis={"visible": False, "range": [-.1, 1.1]},
            yaxis={"visible": False, "range": [0.12, .88]},
            showlegend=False,
            margin={"l": 24, "r": 24, "t": 24, "b": 24},
        )
    )
    st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
    st.warning("Edges indicate only that TinyFish returned a source with this report. They do not prove a relationship between the target and a source.")
    for index, item in enumerate(sources, start=1):
        render_evidence_card(item, index)


def render_timeline() -> None:
    render_topbar("Investigation timeline", "Review timestamped report and evidence records from your history.")
    report = select_investigation_for_view("No investigation timeline")
    if report:
        render_report(report)


def render_unavailable_module(page: str) -> None:
    render_topbar(page, "Capability status for this local ScamShield installation.")
    unavailable: dict[str, tuple[str, str]] = {
        "Scam alerts": (
            "Community alerts and moderation are not implemented.",
            "There is no public submission feed or review workflow. Private watchlist monitoring alerts are available in the Monitoring alerts page.",
        ),
    }
    heading, message = unavailable[page]
    with st.container(border=True):
        render_illustration(
            {
                "Screenshot analyzer": "document-scan.svg",
                "QR scanner": "qr-security.svg",
                "AI security assistant": "assistant.svg",
                "Scam alerts": "phishing-net.svg",
            }[page],
            heading,
        )
        st.markdown(f"### {heading}")
        st.write(message)
        st.caption("This feature is deliberately disabled rather than simulated.")


def render_help() -> None:
    render_topbar("Help & support", "Safe use guidance and current service boundaries.")
    for title, body in [
        ("Do not share secrets", "Never submit passwords, one-time codes, payment PINs, private keys or confidential documents."),
        ("Verify sources independently", "Open original sources yourself, compare context, and do not treat search allegations as verified facts."),
        ("Remote URL fetching", "The remote Fetch service can follow redirects; local URL checks do not guarantee destination safety after redirection."),
        ("Account recovery", "There is no email reset service. A signed-in user may change their password in Profile."),
    ]:
        with st.container(border=True):
            st.markdown(f"### {title}")
            st.write(body)


def render_risk_methodology() -> None:
    render_topbar("Risk methodology", "A transparent screening model—not a fraud verdict.")
    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        with st.container(border=True):
            render_section_title("How the score is built")
            st.write(
                "The current analyzer is deterministic and rule-based. Each configured pattern contributes its documented points when matched. Contributions are summed and capped at 100."
            )
            st.write("Missing information does not add risk points. Search-result allegations are labeled separately from direct page observations and rule-based inferences.")
            st.code(
                "risk_score = min(100, sum(matched_indicator.score_contribution))",
                language="python",
            )
    with right:
        with st.container(border=True):
            render_section_title("Risk bands")
            for (low, high), label in zip(
                ((0, 24), (25, 49), (50, 74), (75, 100)),
                RISK_COLORS,
            ):
                color = risk_color(label)
                st.markdown(
                    f'<div class="legend-line"><span style="background:{color}"></span>'
                    f'<b>{low}–{high}</b>&nbsp; {html.escape(label)}</div>',
                    unsafe_allow_html=True,
                )
    st.warning(
        "A low score is not a guarantee of safety. A score is not a probability, legal conclusion, or proof of wrongdoing. Verify critical claims independently."
    )
    st.info("Confidence and information completeness are reported independently from the risk score.")


def render_about() -> None:
    render_topbar("About ScamShield AI", "Practical web investigation with transparent, human-reviewable signals.")
    st.markdown(
        """
        <div class="hero-panel compact-hero">
          <div class="hero-glow"></div>
          <div class="hero-copy"><div class="eyebrow">RESPONSIBLE INTELLIGENCE</div>
            <h2>Investigate Smart.<br><span>Detect Scams. Stay Protected.</span></h2>
            <p>ScamShield combines live TinyFish Search and Fetch evidence with local deterministic rules. It does not use a language model or claim to determine whether a person or company committed fraud.</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cols = st.columns(3)
    facts = [
        ("01", "Live web evidence", "TinyFish Search returns ranked public results; Fetch returns extracted content for submitted URLs."),
        ("02", "Explainable screening", "Each matched rule exposes its evidence excerpt and score contribution."),
        ("03", "Human review", "Allegations, rule inferences and verified details are distinct; users should check original sources."),
    ]
    for col, (number, title, body) in zip(cols, facts):
        with col:
            with st.container(border=True):
                st.markdown(f'<div class="feature-number">{number}</div>', unsafe_allow_html=True)
                st.markdown(f"### {title}")
                st.write(body)
    st.caption("Stack: Python · FastAPI · Streamlit · TinyFish Search & Fetch · SQLite · Plotly")
    st.warning("This platform is a screening aid, not legal advice or a guarantee of safety. Do not enter credentials, OTPs, or sensitive account details.")
    if not st.session_state.get("auth_token") and st.button("← Back to public home"):
        st.session_state.pop("show_public_about", None)
        st.session_state.pop("main_navigation", None)
        st.rerun()


PUBLIC_PAGES = [
    "Home", "Features", "Solutions", "How it works",
    "Threat intelligence", "Security methodology", "About",
    "FAQ", "Contact", "Privacy policy", "Terms",
]


def render_public_navigation() -> str:
    current = st.session_state.get("public_page", "Home")
    selected = st.selectbox(
        "Explore ScamShield",
        PUBLIC_PAGES,
        index=PUBLIC_PAGES.index(current) if current in PUBLIC_PAGES else 0,
        label_visibility="collapsed",
        key="public_page_nav",
    )
    st.session_state["public_page"] = selected
    return selected


def render_landing() -> None:
    render_ambient_scene("landing")
    healthy, _ = service_status()
    status_text = "API ONLINE" if healthy else "API OFFLINE"
    status_class = "online" if healthy else "offline"
    selected_public_page = render_public_navigation()
    if selected_public_page != "Home":
        render_public_page(selected_public_page)
        return
    st.markdown(
        f'<div class="landing-nav"><div class="brand-lockup landing-brand">'
        f'<div class="brand-mark"><svg viewBox="0 0 48 48" aria-hidden="true">'
        f'<path d="M24 4 41 11v12c0 11-7.4 17.8-17 22C14.4 40.8 7 34 7 23V11z" fill="none" stroke="#2457FF" stroke-width="2.8"/>'
        f'<path d="m16 24 5 5 11-12" fill="none" stroke="#C7F000" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg></div>'
        f'<div><strong>SCAMSHIELD</strong><span>THREAT INTELLIGENCE</span></div></div>'
        f'<div class="nav-right"><span class="status-dot {status_class}"></span>'
        f'{status_text}<span class="nav-divider"></span>TINYFISH SEARCH + FETCH</div></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <div class="hero-panel">
          <div class="hero-glow"></div>
          <div class="hero-copy">
            <div class="eyebrow"><span class="eyebrow-line"></span> TRUST, VERIFIED WITH EVIDENCE</div>
            <h1>Your Digital World.<br><span>Protected by Intelligence.</span></h1>
            <p>Investigate suspicious websites, job offers and payment requests with live web evidence and transparent risk signals.</p>
            <div class="hero-note"><span class="status-dot online"></span> TinyFish research on demand &nbsp;·&nbsp; Rule-based analysis &nbsp;·&nbsp; Human-reviewed</div>
          </div>
          <div class="hero-visual" aria-hidden="true">
            <div class="orbit orbit-one"></div><div class="orbit orbit-two"></div>
            <div class="hero-radar"></div>
            <div class="shield-core"><div class="shield-inner">S</div></div>
            <div class="signal-card signal-top"><span>WEB SIGNAL</span><b>Search on request</b><i>SEARCH · FETCH</i></div>
            <div class="signal-card signal-bottom"><span>RISK MODEL</span><b>Transparent by design</b><i>HUMAN REVIEW</i></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right, blank = st.columns([1.25, 1.2, 4], gap="small")
    with left:
        if st.button("Start investigation  →", type="primary", width="stretch"):
            st.session_state["show_auth_portal"] = True
            st.session_state["auth_mode"] = "Create account"
            st.rerun()
    with right:
        if st.button("Explore the platform", width="stretch"):
            st.session_state["public_page"] = "Features"
            st.rerun()
    with blank:
        sign_in_col, create_col = st.columns(2)
        with sign_in_col:
            if st.button("Sign in"):
                st.session_state["show_auth_portal"] = True
                st.session_state["auth_mode"] = "Sign in"
                st.rerun()
        with create_col:
            if st.button("Create account"):
                st.session_state["show_auth_portal"] = True
                st.session_state["auth_mode"] = "Create account"
                st.rerun()

    st.markdown("#### Start with a public URL")
    url_col, action_col = st.columns([3, 1])
    with url_col:
        st.text_input(
            "Website URL to investigate",
            placeholder="https://example.com",
            key="public_url",
            label_visibility="collapsed",
        )
    with action_col:
        if st.button("Investigate URL", type="primary", width="stretch"):
            candidate = st.session_state.get("public_url", "").strip()
            if not candidate:
                st.warning("Enter a website URL to continue.")
            else:
                st.session_state["queued_url"] = candidate
                st.session_state["show_auth_portal"] = True
                st.session_state["auth_mode"] = "Sign in"
                st.rerun()
    st.caption("The live research request starts after you sign in. URL validation is enforced by the API.")

    render_section_title("Clarity for the moments that matter", "A focused investigation workflow, from signal to source.")
    feature_columns = st.columns(4, gap="medium")
    features = [
        ("01", "Website intelligence", "Combine public search results with fetched site content.", "scanner.svg"),
        ("02", "Offer verification", "Research company and recruitment context before you respond.", "job-shield.svg"),
        ("03", "Message screening", "Spot urgency, credential requests and payment pressure.", "message-warning.svg"),
        ("04", "Payment review", "Review warning language without pretending to verify account ownership.", "payment-shield.svg"),
    ]
    for column, (number, title, text, illustration) in zip(feature_columns, features):
        with column:
            with st.container(border=True):
                render_illustration(illustration, title)
                st.markdown(f'<div class="feature-number">{number}</div>', unsafe_allow_html=True)
                st.markdown(f"### {title}")
                st.write(text)

    explainer, evidence = st.columns([1, 1], gap="large")
    with explainer:
        with st.container(border=True):
            st.markdown('<div class="eyebrow">HOW IT WORKS</div>', unsafe_allow_html=True)
            st.markdown("### From a suspicious signal to a sourced review")
            for number, title, text in [
                ("01", "Submit a target", "Choose a website, offer, message or payment request."),
                ("02", "Collect evidence", "TinyFish Search and Fetch provide live web results when requested."),
                ("03", "Review the signals", "Rule matches, source allegations and information gaps stay visible."),
            ]:
                st.markdown(
                    f'<div class="process-row"><span>{number}</span><div><b>{title}</b><small>{text}</small></div></div>',
                    unsafe_allow_html=True,
                )

    with evidence:
        with st.container(border=True):
            render_illustration("network.svg", "Abstract public-source relationship network")
            st.markdown('<div class="eyebrow">BUILT FOR RESPONSIBLE REVIEW</div>', unsafe_allow_html=True)
            st.markdown("### Intelligence is evidence. Not a verdict.")
            st.write("Search and Fetch can surface sources and page content. Rules identify specific patterns; users review the original source and context.")
            st.markdown('<div class="landing-callout">No fabricated metrics. No hidden model. No guarantee of safety.</div>', unsafe_allow_html=True)

    st.markdown(
        '<div class="landing-footer"><span>SCAMSHIELD AI</span>'
        '<span>Investigate Smart. Detect Scams. Stay Protected.</span>'
        '<span>Rule-based screening · not legal advice</span></div>',
        unsafe_allow_html=True,
    )


def render_public_page(page: str) -> None:
    render_ambient_scene("landing")
    healthy, service = service_status()
    st.markdown(
        '<div class="landing-nav"><div class="brand-lockup landing-brand">'
        '<div class="brand-mark"><span style="color:#2457FF;font-size:1.55rem;font-weight:800">S</span></div>'
        '<div><strong>SCAMSHIELD</strong><span>INVESTIGATE SMART</span></div></div>'
        f'<div class="nav-right"><span class="status-dot {"online" if healthy else "offline"}"></span>'
        f'{html.escape(service)}</div></div>',
        unsafe_allow_html=True,
    )
    details: dict[str, tuple[str, str, list[tuple[str, str]]]] = {
        "Features": (
            "Evidence-first investigation",
            "Use the capabilities that are connected; the rest are labelled plainly.",
            [
                ("URL intelligence", "TinyFish Search and Fetch are used for real public evidence. Redirect and remote-fetch limitations remain."),
                ("Message and payment screening", "Local deterministic rules show the matched pattern and score contribution. Submitted text is not stored verbatim."),
                ("Job and company lookups", "Public search evidence is shown with source links. Search results are not identity or fraud verification."),
                ("Private history", "Reports, saved records, dashboard metrics and watchlist are scoped to your account."),
            ],
        ),
        "Solutions": (
            "One investigation workspace",
            "Designed for people reviewing suspicious online interactions and offers.",
            [
                ("Consumers", "Screen messages, links and payment language before taking action."),
                ("Job seekers", "Review recruitment claims and fee requests alongside public search records."),
                ("Small teams", "Keep reports and manual follow-up items in per-account history."),
            ],
        ),
        "How it works": (
            "From question to evidence",
            "ScamShield collects public evidence where requested, then presents transparent screening results.",
            [
                ("01 · Submit", "Choose a website, offer, message, payment, company, domain, email or phone lookup."),
                ("02 · Research", "Live TinyFish Search/Fetch requests occur only for supported tools. Sensitive identifiers require user consent."),
                ("03 · Review", "Inspect original sources, distinguish source facts from allegations and rules, and decide independently."),
            ],
        ),
        "Threat intelligence": (
            "Public-source intelligence",
            "The application currently uses TinyFish Search and Fetch for website and offer research.",
            [
                ("Sources", "Each returned source is linked so claims can be checked in context."),
                ("Boundaries", "No VirusTotal verdict, domain registration assertion or external threat feed is claimed."),
                ("Remote fetch", "Redirect/destination security is limited by controls exposed by TinyFish Fetch; review the README security notes."),
            ],
        ),
        "Security methodology": (
            "Transparent screening",
            "Risk signals come from configured deterministic rules, not an LLM-generated verdict.",
            [
                ("Scoring", "Matched rule contributions are summed and capped. Missing information adds no points."),
                ("Evidence types", "Verified observations, public allegations and rule-based inferences are distinguished."),
                ("Interpretation", "Scores are not probabilities, proof or a guarantee of safety."),
            ],
        ),
        "About": (
            "ScamShield AI",
            "Investigate Smart. Detect Scams. Stay Protected.",
            [
                ("Purpose", "A practical, human-reviewed screening aid for suspicious websites, offers and messages."),
                ("Current stack", "Python · FastAPI · Streamlit · TinyFish Search & Fetch · SQLite · Plotly."),
            ],
        ),
        "FAQ": (
            "Frequently asked questions",
            "What the current build does—and does not—do.",
            [
                ("Does it use AI?", "Optional Gemini interpretations are available when configured and explicitly requested. They are labeled as AI-generated and never change rule-based scores."),
                ("Is a low score a safety guarantee?", "No. Scores reflect only available configured indicators."),
                ("Are watchlist checks automatic?", "Only domains and organizations you explicitly opt in to monitor are checked on the configured schedule while the backend is running."),
                ("Can I recover a forgotten password by email?", "Not currently. No email delivery service is configured."),
            ],
        ),
        "Contact": (
            "Help and support",
            "No support email or ticket service has been configured in this local build.",
            [
                ("Local operator", "Contact the person or team who operates this ScamShield installation."),
                ("Sensitive data", "Do not send API keys, passwords, OTPs, or private documents to support."),
            ],
        ),
        "Privacy policy": (
            "Privacy notes",
            "This local app stores account data and completed investigation records in its configured SQLite database.",
            [
                ("Account records", "Email, display name, scrypt password hash, role and hashed session records are stored server-side."),
                ("Investigation data", "Reports are per-user. Message/payment submissions are not persisted verbatim; website URLs, public evidence, report outputs, and any submitted email/phone intelligence target are stored."),
                ("Third-party research", "Submitted URLs and explicitly authorized public-search identifiers may be sent to TinyFish. Review TinyFish policies before use."),
                ("Operations", "The deployment owner controls retention, backups, access to the host and database. This is informational copy, not legal advice."),
            ],
        ),
        "Terms": (
            "Use limitations",
            "ScamShield is an informational screening aid, not legal, financial, employment, or security advice.",
            [
                ("Authorized use", "Only submit information and URLs you are authorized to investigate."),
                ("No verdict", "Do not treat risk categories, allegations, or search results as proof of wrongdoing."),
                ("Service boundaries", "Results can be incomplete, stale, misleading or about unrelated parties. Verify important claims independently."),
                ("Local deployment", "The operator must secure the server, configure TLS for remote access, protect the database, and define retention terms."),
            ],
        ),
    }
    title, intro, items = details[page]
    render_topbar(title, intro)
    if page == "Features":
        visuals = [
            ("scanner.svg", "Live public website source collection"),
            ("job-shield.svg", "Recruitment offer screening aid"),
            ("message-warning.svg", "Message warning-pattern screening"),
            ("payment-shield.svg", "Payment request screening"),
            ("qr-security.svg", "Decode and inspect QR destinations before explicit investigation"),
            ("document-scan.svg", "Local OCR screening for uploaded screenshots"),
            ("evidence-graph.svg", "Evidence relationship graph illustration"),
            ("assistant.svg", "Optional evidence-grounded Gemini interpretation"),
        ]
        cols = st.columns(4)
        for col, (asset, label) in zip(cols * 2, visuals):
            with col:
                with st.container(border=True):
                    render_illustration(asset, label)
                    st.caption(label)
    for heading, body in items:
        with st.container(border=True):
            st.markdown(f"### {heading}")
            st.write(body)
    if page == "Privacy policy":
        st.warning("This is an implementation summary, not a legally reviewed privacy policy. A production operator must publish jurisdiction-specific terms and retention details.")
    if page == "Terms":
        st.warning("Draft service limitations only. Obtain legal review before treating this page as binding terms.")
    if page == "Contact":
        st.info("A contact form is not provided because no backend mail/ticket delivery has been configured.")
    col, _ = st.columns([1, 4])
    with col:
        if st.button("Back to home", width="stretch"):
            st.session_state["public_page"] = "Home"
            st.rerun()
def render_auth_portal() -> None:
    render_ambient_scene("auth")
    modes = ["Sign in", "Create account"]
    st.session_state.setdefault("auth_mode", "Sign in")
    mode = st.radio(
        "Account action",
        modes,
        horizontal=True,
        label_visibility="collapsed",
        key="auth_mode",
    )
    intro_title = "Your next decision deserves better evidence."
    intro_copy = (
        "Review public sources, inspect exact job listings, and understand warning "
        "signals before you act."
    )
    if mode == "Create account":
        intro_title = "Build a safer place to investigate."
        intro_copy = (
            "Create a private workspace for evidence-led website, job, message, "
            "and offer reviews."
        )
    st.markdown(
        f"""
        <section class="auth-welcome">
          <div class="auth-welcome-copy">
            <span class="eyebrow"><span class="eyebrow-line"></span> SCAMSHIELD AI · PRIVATE WORKSPACE</span>
            <h1>{html.escape(intro_title)}</h1>
            <p>{html.escape(intro_copy)}</p>
            <div class="auth-proof-row">
              <span><b>01</b> Source-backed research</span>
              <span><b>02</b> Explainable signals</span>
              <span><b>03</b> Human-reviewed decisions</span>
            </div>
          </div>
          <div class="auth-shield" aria-hidden="true">
            <div class="auth-shield-ring auth-shield-ring--outer"></div>
            <div class="auth-shield-ring auth-shield-ring--inner"></div>
            <div class="auth-shield-radar"></div>
            <div class="auth-shield-core"><span>S</span></div>
            <i class="auth-node auth-node--a"></i><i class="auth-node auth-node--b"></i>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="auth-form-heading"><div class="eyebrow">SECURE ACCOUNT ACCESS</div>'
        f'<h2>{"Create your account" if mode == "Create account" else "Welcome back"}</h2>'
        f'<p>{"Your private workspace starts here." if mode == "Create account" else "Sign in to continue to your investigations."}</p></div>',
        unsafe_allow_html=True,
    )
    with st.container(border=True, key="auth-form-panel"):
        display_name = ""
        confirm_password = ""
        if mode == "Create account":
            email = st.text_input(
                "Email",
                max_chars=254,
                autocomplete="email",
                key="register_email",
            )
            display_name = st.text_input(
                "Display name",
                max_chars=80,
                autocomplete="name",
                key="register_display_name",
            )
            password = st.text_input(
                "Password",
                type="password",
                max_chars=128,
                help="Use at least 12 characters.",
                autocomplete="new-password",
                key="register_password",
            )
            confirm_password = st.text_input(
                "Confirm password",
                type="password",
                max_chars=128,
                autocomplete="new-password",
                key="register_password_confirm",
            )
            strength = sum(
                (
                    len(password) >= 12,
                    any(char.isalpha() for char in password),
                    any(char.isdigit() for char in password),
                    any(not char.isalnum() for char in password),
                )
            )
            strength_label = ("Not started", "Weak", "Fair", "Good", "Strong")[strength]
            st.progress(strength / 4, text=f"Password strength: {strength_label}")
            st.caption("Aim for 12+ characters, with a mix of letters, numbers, and symbols.")
            submitted = st.button(
                "Create account",
                type="primary",
                width="stretch",
                key="register_submit",
            )
        else:
            with st.form("account-access-form"):
                email = st.text_input("Email", max_chars=254, autocomplete="email")
                password = st.text_input(
                    "Password",
                    type="password",
                    max_chars=128,
                    autocomplete="current-password",
                )
                submitted = st.form_submit_button(
                    "Sign in securely",
                    type="primary",
                    width="stretch",
                )
        if submitted:
            if mode == "Create account" and password != confirm_password:
                st.error("Passwords do not match.")
            elif mode == "Create account" and len(password) < 12:
                st.error("Use a password with at least 12 characters.")
            elif mode == "Create account" and not display_name.strip():
                st.error("Enter a display name.")
            else:
                route = "/api/auth/register" if mode == "Create account" else "/api/auth/login"
                payload = {"email": email, "password": password}
                if mode == "Create account":
                    payload["display_name"] = display_name
                with st.spinner(
                    "Creating your secure workspace..."
                    if mode == "Create account"
                    else "Signing in..."
                ):
                    result = api_call("POST", route, json=payload)
                if result:
                    clear_active_report()
                    st.session_state["auth_token"] = result["access_token"]
                    st.session_state["account"] = result["user"]
                    queued_url = st.session_state.pop("queued_url", None)
                    if queued_url:
                        st.session_state["website_url"] = queued_url
                        st.session_state["investigation_mode"] = "Website"
                        st.session_state["main_navigation"] = "URL scanner"
                    else:
                        st.session_state["main_navigation"] = "Overview"
                    st.session_state["show_auth_portal"] = False
                    st.rerun()
    if mode == "Create account":
        st.caption("Local accounts use hashed passwords and private report ownership. Email verification and email-based password recovery are not configured.")
    else:
        st.caption("Forgot your password? Email-based recovery is unavailable because no mail service is configured. If signed in, you can change it from Account settings.")
    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.success(notice)
    if st.button("← Back to public home"):
        st.session_state["show_auth_portal"] = False
        st.rerun()


def main() -> None:
    render_ambient_scene("workspace")
    selected = render_sidebar()
    if selected in {"Overview", "Analytics"}:
        render_overview()
    elif selected in {
        "New investigation", "URL scanner", "Message scanner",
        "Job scam detector", "Email scam detection", "Payment scam checker",
        "Email intelligence", "Phone intelligence",
        "Company intelligence", "Domain intelligence",
    }:
        mode_for_page = {
            "URL scanner": "Website",
            "Message scanner": "Message",
            "Job scam detector": "Offer",
            "Email scam detection": "Email Scam Analysis",
            "Payment scam checker": "Payment",
            "Email intelligence": "Email Intelligence",
            "Phone intelligence": "Phone Intelligence",
            "Company intelligence": "Company Intelligence",
            "Domain intelligence": "Domain Intelligence",
        }
        if selected in mode_for_page:
            st.session_state["investigation_mode"] = mode_for_page[selected]
        render_investigation_workspace()
    elif selected == "Threat intelligence":
        render_threat_intelligence()
    elif selected == "History":
        render_history()
    elif selected == "Investigation timeline":
        render_timeline()
    elif selected == "Evidence graph":
        render_evidence_graph()
    elif selected == "Saved reports":
        render_saved_reports()
    elif selected == "Watchlist":
        render_watchlist()
    elif selected == "Scam alerts":
        render_monitoring_alerts()
    elif selected == "Batch URL investigation":
        render_batch_investigation()
    elif selected == "Screenshot analyzer":
        render_screenshot_analyzer()
    elif selected == "QR scanner":
        render_qr_scanner()
    elif selected == "AI security assistant":
        render_ai_assistant()
    elif selected == "Integrations":
        render_integrations()
    elif selected in {"Profile", "Settings"}:
        render_account()
    elif selected == "Admin":
        render_admin()
    elif selected == "Risk methodology":
        render_risk_methodology()
    elif selected == "Help & support":
        render_help()
    else:
        render_unavailable_module(selected)


if st.session_state.get("auth_token"):
    main()
elif st.session_state.get("show_auth_portal"):
    render_auth_portal()
elif st.session_state.pop("show_public_about", False):
    render_about()
else:
    render_landing()
