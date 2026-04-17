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
.main .block-container { max-width: 1100px; padding-top: 1.5rem; }
footer { display: none !important; }
#MainMenu { visibility: hidden; }
.stDeployButton { display: none; }

/* ── Page header ── */
.gh-page-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px 0 20px 0;
    border-bottom: 1px solid #d0d7de;
    margin-bottom: 20px;
}
.gh-page-title {
    font-size: 20px;
    font-weight: 600;
    color: #1f2328;
    margin: 0;
}
.gh-page-subtitle {
    font-size: 13px;
    color: #636c76;
    margin: 0;
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

/* ── Tab Spacing Fix ── */
.stTabs [data-baseweb="tab-list"] button {
    margin-right: 8px !important;
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

/* ── Tabs ── */
button[data-baseweb="tab"] { background: transparent !important; gap: 0 !important; }
div[data-baseweb="tab"] {
    border-radius: 0 !important;
    border: none !important;
    padding: 8px 16px !important;
    font-size: 14px !important;
}
div[aria-selected="true"][data-baseweb="tab"] {
    border-bottom: 2px solid #fd8c73 !important;
    font-weight: 600 !important;
    color: #1f2328 !important;
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
</style>
"""
