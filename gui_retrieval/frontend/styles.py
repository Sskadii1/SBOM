"""
frontend/styles.py — Shared CSS styles for the Streamlit web application.
"""

GITHUB_CSS = """
<style>
/* ── Google Font ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

/* ── Reset Streamlit chrome ── */
html, body, [class*="css"] {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", "Noto Sans",
                 Helvetica, Arial, sans-serif !important;
    font-size: 14px;
    color: #1f2328;
}
html,
body {
    scrollbar-gutter: stable;
}
section[data-testid="stMain"] {
    scrollbar-gutter: stable;
    overflow-y: scroll;
}
.main .block-container { max-width: 1400px; padding-top: 1.25rem; padding-bottom: 1rem; }
footer { display: none !important; }
#MainMenu { visibility: hidden; }
.stDeployButton { display: none; }

/* ── Dashboard shell + header ── */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor) {
    border: 1px solid #d8dee4;
    border-radius: 18px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    overflow: hidden;
    width: calc(100% - 34px) !important;
    margin-left: 17px !important;
    margin-right: 17px !important;
    margin-bottom: 18px;
    box-shadow: 0 8px 24px rgba(31, 35, 40, 0.04);
}
.gh-page-header {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 20px;
    border-bottom: 1px solid #d8dee4;
    border-radius: 0;
    margin-bottom: 0;
    background: transparent;
}
.gh-page-header-icon {
    width: 40px;
    height: 40px;
    flex-shrink: 0;
}
.gh-page-title {
    font-size: 18px;
    font-weight: 600;
    color: #1f2328;
    margin: 0;
}
.gh-page-subtitle {
    font-size: 13px;
    color: #636c76;
    margin: 0;
}

/* ── Tab navigation ── */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor) div[data-testid="stHorizontalBlock"] {
    padding: 12px 14px;
    gap: 8px;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor) div[data-testid="stButton"] > button,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-repo-nav-anchor) div[data-testid="stButton"] > button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    min-height: 40px;
    padding: 9px 13px;
    border-radius: 10px;
    border: 1px solid #d8dee4;
    background: #ffffff;
    color: #57606a;
    font-size: 14px;
    line-height: 1.2;
    font-weight: 500;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
    transition: background 0.18s ease, border-color 0.18s ease, color 0.18s ease, box-shadow 0.18s ease;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor) div[data-testid="stButton"] > button:hover,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-repo-nav-anchor) div[data-testid="stButton"] > button:hover {
    background: #f6f8fa;
    color: #24292f;
    border-color: #8c959f;
    box-shadow: 0 2px 8px rgba(27, 31, 36, 0.06);
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor) div[data-testid="stButton"] > button[kind="primary"],
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-repo-nav-anchor) div[data-testid="stButton"] > button[kind="primary"] {
    background: #fff1e5;
    border-color: #fd8c73;
    color: #24292f;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(253, 140, 115, 0.16);
}

div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-repo-nav-anchor) {
    border: 1px solid #d8dee4;
    border-radius: 14px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    overflow: hidden;
    margin: 10px 0 14px 0;
    padding: 12px 14px;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-repo-nav-anchor) div[data-testid="stHorizontalBlock"] {
    gap: 8px;
}

div[data-testid="stVerticalBlock"].st-key-gh-content-shell {
    box-sizing: border-box;
    width: calc(100% - 34px) !important;
    margin-left: 17px !important;
    margin-right: 17px !important;
    margin-top: 6px;
    margin-bottom: 14px;
    padding: 18px 20px 16px 20px !important;
    border: 1px solid #d8dee4 !important;
    border-radius: 20px !important;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%) !important;
    box-shadow: 0 8px 24px rgba(31, 35, 40, 0.04) !important;
}
div[data-testid="stVerticalBlock"].st-key-gh-content-shell > div[data-testid="stElementContainer"]:has(.gh-content-shell-anchor),
div[data-testid="stVerticalBlock"].st-key-gh-content-shell > div[data-testid="stElementContainer"]:has(.gh-content-shell-end) {
    display: none !important;
}

/* Report layout foundation */
.gh-report-shell {
    max-width: 1420px;
    margin: 0 auto;
}
.gh-report-block {
    border: 1px solid #d8dee4;
    border-radius: 14px;
    background: #fff;
    padding: 14px 16px;
    margin-bottom: 14px;
    box-shadow: 0 6px 18px rgba(31, 35, 40, 0.04);
}
.gh-report-block h4 {
    margin: 0 0 8px 0;
    font-size: 1.04rem;
}
.gh-report-subtitle {
    margin: 0 0 10px 0;
    color: #57606a;
    font-size: 13px;
}
.gh-report-note {
    color: #57606a;
    font-size: 12px;
}

/* Assessment panel */
.gh-assess-panel {
    border: 1px solid #d8dee4;
    border-radius: 14px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    padding: 14px 16px;
    margin: 10px 0 14px 0;
}
.gh-assess-title {
    font-size: 16px;
    font-weight: 650;
    color: #1f2328;
    margin-bottom: 10px;
}
.gh-assess-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 10px;
}
.gh-assess-card {
    border: 1px solid #d8dee4;
    border-radius: 12px;
    background: #fff;
    padding: 10px 12px;
}
.gh-assess-card-title {
    font-size: 14px;
    font-weight: 600;
    color: #1f2328;
    margin-bottom: 2px;
}
.gh-assess-card-subtitle {
    font-size: 12px;
    color: #57606a;
    margin-bottom: 6px;
}
.gh-assess-card ul {
    margin: 0;
    padding-left: 18px;
    color: #1f2328;
    font-size: 12px;
    line-height: 1.35;
}

/* compact badge/pill rows */
.gh-pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 8px 0 0 0;
}
.gh-pill {
    border-radius: 999px;
    border: 1px solid #d0d7de;
    padding: 3px 9px;
    font-size: 12px;
    color: #1f2328;
    background: #f6f8fa;
}

/* mobile behavior */
@media (max-width: 1100px) {
    .gh-assess-grid {
        grid-template-columns: 1fr;
    }
    .main .block-container {
        padding-left: 0.8rem;
        padding-right: 0.8rem;
    }
    div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-dashboard-shell-anchor),
    div[data-testid="stVerticalBlock"].st-key-gh-content-shell {
        width: 100% !important;
        margin-left: 0 !important;
        margin-right: 0 !important;
    }
    div[data-testid="stVerticalBlock"].st-key-gh-content-shell {
        padding-left: 14px !important;
        padding-right: 14px !important;
    }
}
.gh-enterprise-kpi-anchor,
.gh-repository-selector-anchor,
.gh-dashboard-shell-anchor,
.gh-primary-tabs-anchor,
.gh-repo-nav-anchor,
.gh-content-shell-anchor,
.gh-content-shell-end {
    width: 0;
    height: 0;
}

.st-key-report-export-button div[data-testid="stButton"] > button {
    min-height: 38px;
    padding: 8px 14px;
    border-radius: 10px;
    border: 1px solid #0f5f6d;
    background: #127c8a;
    color: #ffffff;
    font-size: 13.5px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(18, 124, 138, 0.18);
    transition: background 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease, transform 0.18s ease;
}
.st-key-report-export-button div[data-testid="stButton"] > button:hover {
    background: #1691a1;
    border-color: #0b4f5b;
    color: #ffffff;
    box-shadow: 0 6px 16px rgba(18, 124, 138, 0.24);
    transform: translateY(-1px);
}

/* ── Severity count pills (top stats bar) ── */
.gh-stats-bar {
    display: flex;
    gap: 16px;
    align-items: center;
    padding: 12px 0;
    margin-bottom: 16px;
    flex-wrap: wrap;
}
.gh-stat-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    font-weight: 500;
    padding: 4px 10px;
    border-radius: 20px;
    border: 1px solid;
    cursor: pointer;
    user-select: none;
    transition: opacity 0.15s;
}
.gh-stat-pill:hover { opacity: 0.8; }
.pill-critical  { color: #cf222e; background: #ffebe9; border-color: #cf222e44; }
.pill-high      { color: #953800; background: #fff1e5; border-color: #95380044; }
.pill-medium    { color: #9a6700; background: #fff8c5; border-color: #9a670044; }
.pill-low       { color: #636c76; background: #f6f8fa; border-color: #d0d7de; }
.pill-kev       { color: #8250df; background: #fbefff; border-color: #8250df44; }
.pill-total     { color: #1f2328; background: #f6f8fa; border-color: #d0d7de; font-weight: 600; }

div[data-testid="stVerticalBlock"]:has(.gh-enterprise-kpi-anchor) [data-testid="stMetric"] {
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    border: 1px solid #d8dee4;
    border-radius: 14px;
    padding: 14px 16px;
    box-shadow: 0 6px 16px rgba(31, 35, 40, 0.04);
}
div[data-testid="stVerticalBlock"]:has(.gh-enterprise-kpi-anchor) [data-testid="stMetricLabel"] {
    color: #57606a !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}
div[data-testid="stVerticalBlock"]:has(.gh-enterprise-kpi-anchor) [data-testid="stMetricValue"] {
    color: #1f2328 !important;
    font-size: 2rem !important;
    font-weight: 650 !important;
}

div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) label[data-testid="stWidgetLabel"] p {
    color: #57606a !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] > div {
    min-height: 46px;
    height: 46px;
    box-sizing: border-box !important;
    display: flex !important;
    align-items: center !important;
    border-radius: 12px !important;
    border: 1px solid #d0d7de !important;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%) !important;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] > div:hover {
    border-color: #f28c52 !important;
    box-shadow: 0 0 0 4px rgba(242, 140, 82, 0.12);
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] span,
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] input {
    font-size: 15px !important;
    color: #1f2328 !important;
    line-height: 1.25 !important;
    padding-top: 0 !important;
    padding-bottom: 0 !important;
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] > div > div {
    display: flex !important;
    align-items: center !important;
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] svg {
    align-self: center !important;
}
/* Allow selecting and replacing text while searching in the repository selector. */
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) [data-testid="stSelectbox"],
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"],
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] > div,
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] > div > div,
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) [data-baseweb="input"],
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) [data-baseweb="base-input"] {
    user-select: text !important;
    -webkit-user-select: text !important;
    -moz-user-select: text !important;
}
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) div[data-baseweb="select"] input,
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) [data-baseweb="input"] input,
div[data-testid="stVerticalBlock"]:has(.gh-repository-selector-anchor) [data-baseweb="base-input"] input,
.stSelectbox input,
.stTextInput input,
[data-testid="stSelectbox"] input,
[data-testid="stTextInput"] input,
[data-baseweb="select"] input,
[data-baseweb="input"] input {
    user-select: text !important;
    -webkit-user-select: text !important;
    -moz-user-select: text !important;
    pointer-events: auto !important;
    cursor: text !important;
    caret-color: #1f2328 !important;
}

/* ── Alert list header bar ── */
.gh-alert-list-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 0 10px 0;
    background: transparent;
    font-size: 13px;
    color: #636c76;
    font-weight: 500;
    margin-bottom: 12px;
}

/* ── Individual alert row ── */
.gh-alert-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 16px;
    border: 1px solid #d0d7de !important;
    border-radius: 6px !important;
    background: #fff;
    transition: background 0.15s, box-shadow 0.15s;
    margin-bottom: 12px !important;
    cursor: pointer;
}
.gh-alert-row:hover {
    background: #f6f8fa;
    box-shadow: 0 4px 8px rgba(140,149,159,0.1);
}

/* ── Collapse Streamlit gap between adjacent alert cards ── */
[data-testid="stMarkdownContainer"]:has(.gh-alert-row),
[data-testid="stMarkdownContainer"]:has(.gh-alert-list-header) {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}
div.element-container:has(.gh-alert-row),
div.element-container:has(.gh-alert-list-header) {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}
div.stMarkdown:has(.gh-alert-row),
div.stMarkdown:has(.gh-alert-list-header) {
    margin-bottom: 0 !important;
    padding-bottom: 0 !important;
}

/* ── Shield icon ── */
.gh-shield {
    flex-shrink: 0;
    width: 16px;
    height: 16px;
    margin-top: 2px;
}

/* ── Severity badge ── */
.gh-badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 20px;
    border: 1px solid;
    white-space: nowrap;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}
.badge-critical { color: #cf222e; border-color: #cf222e; }
.badge-high     { color: #bc4c00; border-color: #bc4c00; }
.badge-medium   { color: #9a6700; border-color: #9a6700; }
.badge-low      { color: #636c76; border-color: #636c76; }
.badge-kev      { color: #8250df; border-color: #8250df; background: #fff; }

/* ── Metadata row ── */
.gh-alert-meta {
    font-size: 12px;
    color: #636c76;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}

/* ── Fix chip ── */
.gh-fix-chip {
    display: inline-block;
    font-size: 11px;
    color: #1a7f37;
    background: #dafbe1;
    border: 1px solid #1a7f3744;
    border-radius: 20px;
    padding: 1px 8px;
    font-weight: 500;
}
.gh-fix-chip-none {
    display: inline-block;
    font-size: 11px;
    color: #636c76;
    background: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 20px;
    padding: 1px 8px;
}

/* ── Streamlit native button overrides ── */
[data-testid="baseButton-secondary"] {
    background: #f6f8fa !important;
    border: 1px solid #d0d7de !important;
    color: #24292f !important;
    font-size: 12px !important;
    padding: 2px 12px !important;
    min-height: 28px !important;
    font-weight: 500 !important;
    box-shadow: 0 1px 0 rgba(27,31,36,0.04) !important;
    transition: 0.2s cubic-bezier(0.3, 0, 0.5, 1);
}
[data-testid="baseButton-secondary"]:hover {
    background: #f3f4f6 !important;
    border-color: #cfd6dd !important;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #f6f8fa !important;
    border-right: 1px solid #d0d7de !important;
}

/* ── Custom markdown section headings ── */
.gh-section-heading {
    font-size: 16px;
    font-weight: 600;
    color: #1f2328;
    padding-bottom: 8px;
    border-bottom: 1px solid #d0d7de;
    margin: 24px 0 16px 0;
}

/* ── Detail page breadcrumb ── */
/* Analysis markdown polish */
[data-testid="stMarkdownContainer"] h3 {
    margin-top: 1.4rem;
    margin-bottom: 0.6rem;
    font-size: 1.05rem;
    font-weight: 700;
    color: #1f2328;
}
[data-testid="stMarkdownContainer"] p,
[data-testid="stMarkdownContainer"] li {
    line-height: 1.7;
}
[data-testid="stMarkdownContainer"] table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.8rem 0 1rem 0;
    font-size: 0.95rem;
    background: #fff;
    border: 1px solid #d0d7de;
}
[data-testid="stMarkdownContainer"] thead tr {
    background: #f6f8fa;
}
[data-testid="stMarkdownContainer"] th,
[data-testid="stMarkdownContainer"] td {
    padding: 10px 12px;
    border-bottom: 1px solid #d8dee4;
    text-align: left;
    vertical-align: top;
}
[data-testid="stMarkdownContainer"] tr:last-child td {
    border-bottom: none;
}
[data-testid="stMarkdownContainer"] pre {
    background: #f6f8fa;
    border: 1px solid #d0d7de;
    border-radius: 8px;
    padding: 12px 14px;
}
[data-testid="stMarkdownContainer"] code {
    font-size: 0.92em;
}

/* â”€â”€ Detail page breadcrumb â”€â”€ */
/* Detail page breadcrumb */
.gh-breadcrumb {
    display: flex; align-items: center; gap: 8px;
    font-size: 13px; color: #636c76; margin-bottom: 16px;
}
.gh-breadcrumb-sep { color: #d0d7de; }

/* ── Detail hero card ── */
.gh-detail-hero {
    border: 1px solid #d0d7de; border-radius: 6px;
    padding: 20px 24px; margin-bottom: 20px; background: #fff;
}
.gh-detail-title {
    font-size: 20px; font-weight: 600; color: #1f2328;
    display: flex; align-items: center; gap: 12px; margin-bottom: 12px;
}
.gh-detail-meta {
    font-size: 13px; color: #636c76; display: flex; gap: 16px; flex-wrap: wrap;
}

/* ── Detail block cards ── */
.gh-detail-card {
    border: 1px solid #d0d7de; border-radius: 6px;
    margin-bottom: 20px; background: #fff;
}
.gh-detail-card-header {
    background: #f6f8fa; border-bottom: 1px solid #d0d7de;
    padding: 12px 16px; font-weight: 600; font-size: 14px;
    border-radius: 6px 6px 0 0;
}
.gh-detail-card-body {
    padding: 16px; font-size: 13px; line-height: 1.5;
}

/* ── CWE tag ── */
.gh-cwe-tag {
    display: inline-block; font-size: 12px; font-weight: 500;
    color: #9a6700; background: #fff8c5; border: 1px solid #9a670044;
    border-radius: 12px; padding: 2px 10px; margin-right: 6px;
}

/* ── Dependency chain ── */
.gh-dep-chain {
    display: flex; align-items: center; gap: 4px;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
    font-size: 12px; flex-wrap: wrap; margin-bottom: 8px;
}
.gh-dep-node {
    padding: 1px 6px; background: #fff;
    border: 1px solid #d0d7de; border-radius: 4px;
}
.gh-dep-root   { border-color: #0969da; color: #0969da; font-weight: 600; }
.gh-dep-target { border-color: #cf222e; color: #cf222e; font-weight: 600; }
.gh-dep-arrow  { color: #d0d7de; }

/* ── Fix versions ── */
.gh-fix-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
.gh-fix-tag {
    font-size: 12px;
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
    color: #1a7f37; background: #dafbe1; border: 1px solid #1a7f3744;
    border-radius: 4px; padding: 2px 8px; font-weight: 600;
}

code {
    font-family: ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
    background-color: rgba(175, 184, 193, 0.2);
    border-radius: 6px;
    padding: 1px 6px; margin: 2px; font-weight: 500;
}
.gh-chain-card {
    border: 1px solid #d0d7de;
    border-radius: 6px;
    padding: 12px;
    background: #f6f8fa;
    margin-bottom: 12px;
}
.gh-chain-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 10px;
}
.gh-chain-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    border: 1px solid #d0d7de;
    border-radius: 999px;
    background: #fff;
    color: #57606a;
    font-size: 12px;
}

/* Alert toolbar */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) {
    margin: 4px 0 18px 0;
    padding: 14px 16px 8px 16px;
    border: 1px solid #d8dee4;
    border-radius: 12px;
    background: linear-gradient(180deg, #ffffff 0%, #fbfcfe 100%);
    box-shadow: 0 6px 18px rgba(31, 35, 40, 0.04);
}
.gh-alert-toolbar-anchor {
    width: 0;
    height: 0;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stHorizontalBlock"] {
    align-items: flex-end;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) [data-testid="column"] > div {
    display: flex;
    flex-direction: column;
    justify-content: flex-end;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) .gh-alert-toolbar-label {
    margin: 0 0 6px 0;
    color: #57606a;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    line-height: 1.25;
    min-height: 18px;
    display: flex;
    align-items: center;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) label[data-testid="stWidgetLabel"] {
    margin-bottom: 6px !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) label[data-testid="stWidgetLabel"] p {
    color: #57606a !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    margin: 0 !important;
    min-height: 18px;
    display: flex;
    align-items: center;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stPopover"] > div > button,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] > div,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] {
    min-height: 56px;
    height: 56px;
    box-sizing: border-box !important;
    display: flex !important;
    align-items: center !important;
    border-radius: 12px !important;
    border: 1px solid #d0d7de !important;
    background: #ffffff !important;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
    transition: border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stPopover"] > div > button {
    width: 100%;
    height: 100%;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: space-between;
    padding: 0 14px;
    color: #1f2328 !important;
    font-size: 14px !important;
    font-weight: 600 !important;
    background: linear-gradient(180deg, #fff7ed 0%, #fffbf5 100%) !important;
    border-color: #f0c7a1 !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stPopover"],
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stPopover"] > div {
    margin-top: 0 !important;
    margin-bottom: 0 !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stPopover"] > div > button:hover,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] > div:hover,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"]:hover {
    border-color: #f28c52 !important;
    box-shadow: 0 0 0 4px rgba(242, 140, 82, 0.12);
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] {
    min-height: 56px;
    height: 56px;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] input,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] span,
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] input {
    color: #1f2328 !important;
    font-size: 14px !important;
    line-height: 1.25 !important;
    padding-top: 0 !important;
    padding-bottom: 0 !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] > div > div {
    display: flex !important;
    align-items: center !important;
    min-height: 100% !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="select"] svg {
    align-self: center !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] {
    background: #f6f8fa !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] [data-baseweb="base-input"],
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] [data-baseweb="base-input"] > div {
    background: #f6f8fa !important;
    height: 100% !important;
    border-radius: 12px !important;
    display: flex !important;
    align-items: center !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] input {
    height: 100% !important;
    background: #f6f8fa !important;
    line-height: 56px !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-testid="stTextInputRootElement"] input::placeholder {
    color: #8c959f !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="popover"] {
    border-radius: 16px !important;
    border: 1px solid #d8dee4 !important;
    box-shadow: 0 18px 48px rgba(31, 35, 40, 0.14) !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="popover"] [data-testid="stWidgetLabel"] p {
    text-transform: none;
    font-size: 13px !important;
    color: #1f2328 !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .gh-alert-toolbar-anchor) div[data-baseweb="popover"] [data-baseweb="select"] > div {
    min-height: 40px;
    border-radius: 10px !important;
}
</style>
"""
