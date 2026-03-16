CSS = """
<style>
/* ===== HEIMDALL — Warm Slate Light Theme ===== */
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Playfair+Display:wght@700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    /* ── Base surfaces ── */
    --bg-base:        #f0eff5;          /* warm lavender-grey */
    --bg-mid:         #e8e6f0;          /* slightly deeper */
    --bg-gradient:    linear-gradient(145deg, #ede9f6 0%, #eef0f8 40%, #e8edf5 100%);

    /* ── Cards / glass ── */
    --card-bg:        rgba(255, 255, 255, 0.72);
    --card-bg-hover:  rgba(255, 255, 255, 0.92);
    --card-border:    rgba(99, 91, 171, 0.18);
    --card-shadow:    0 4px 24px rgba(60, 50, 120, 0.09);
    --card-shadow-lg: 0 12px 40px rgba(60, 50, 120, 0.14);

    /* ── Indigo accent ── */
    --indigo-900: #1e1b4b;
    --indigo-800: #312e81;
    --indigo-700: #3730a3;
    --indigo-600: #4f46e5;
    --indigo-500: #6366f1;
    --indigo-400: #818cf8;
    --indigo-100: #e0e7ff;
    --indigo-50:  #eef2ff;
    --indigo-glow: rgba(99, 102, 241, 0.15);

    /* ── Coral / rose alert accent ── */
    --coral-600: #e11d48;
    --coral-500: #f43f5e;
    --coral-400: #fb7185;
    --coral-100: #ffe4e6;

    /* ── Teal success accent ── */
    --teal-600:  #0d9488;
    --teal-500:  #14b8a6;
    --teal-400:  #2dd4bf;
    --teal-100:  #ccfbf1;

    /* ── Amber warning ── */
    --amber-600: #d97706;
    --amber-400: #fbbf24;
    --amber-100: #fef3c7;

    /* ── TEXT — always dark, always readable ── */
    --text-primary:   #1a1523;    /* near-black, warm-tinted */
    --text-secondary: #3d3558;    /* dark indigo-grey */
    --text-muted:     #6b6889;    /* readable muted */
    --text-on-accent: #ffffff;    /* white on coloured buttons/banners */

    --border-light: rgba(99, 91, 171, 0.15);
}

/* ===== Base ===== */
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
    background: var(--bg-gradient);
    color: var(--text-primary);
}

.stApp {
    background: var(--bg-gradient);
}

/* Subtle dot-grid texture */
.stApp::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image: radial-gradient(circle, rgba(99,102,241,0.07) 1px, transparent 1px);
    background-size: 28px 28px;
    pointer-events: none;
    z-index: 0;
}

/* ── Force all text readable ── */
.stApp p, .stApp span, .stApp div, .stApp label,
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6,
.stApp li, .stApp td, .stApp th, .stApp a {
    color: var(--text-primary) !important;
}

/* ===== Sidebar ===== */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #ebe8f8 0%, #ddd9ef 100%);
    border-right: 1px solid var(--card-border);
    box-shadow: 3px 0 24px rgba(60,50,120,0.10);
}

[data-testid="stSidebar"] * {
    color: var(--text-primary) !important;
}

[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] div {
    color: var(--text-secondary) !important;
}

[data-testid="stSidebar"] .stRadio label {
    background: rgba(255, 255, 255, 0.65);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 0.6rem 1rem;
    margin-bottom: 6px;
    transition: all 0.2s ease;
    box-shadow: var(--card-shadow);
    font-weight: 600;
    font-size: 0.88rem;
    color: var(--text-secondary) !important;
}

[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(255, 255, 255, 0.90);
    border-color: var(--indigo-500);
    transform: translateX(5px);
    box-shadow: 0 4px 16px var(--indigo-glow);
    color: var(--indigo-700) !important;
}

[data-testid="stSidebar"] .stButton button {
    background: linear-gradient(135deg, var(--indigo-700), var(--indigo-600)) !important;
    border: none !important;
    border-radius: 12px !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    font-weight: 700 !important;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    font-size: 0.78rem !important;
    transition: all 0.2s !important;
    box-shadow: 0 4px 16px var(--indigo-glow) !important;
}

[data-testid="stSidebar"] .stButton button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(99,102,241,0.3) !important;
}

/* ===== Main Title ===== */
.title-container {
    padding: 1.5rem 0 1rem;
    border-bottom: 2px solid var(--indigo-100);
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 16px;
}

.title-icon {
    background: linear-gradient(135deg, var(--indigo-700), var(--indigo-500));
    border-radius: 18px;
    padding: 12px 18px;
    font-size: 2rem;
    box-shadow: 0 6px 24px var(--indigo-glow), 0 2px 8px rgba(0,0,0,0.08);
}

.title-text {
    font-family: 'Playfair Display', serif;
    font-size: 2.1rem;
    font-weight: 800;
    letter-spacing: -0.3px;
    line-height: 1.1;
    color: var(--indigo-900) !important;
    -webkit-text-fill-color: var(--indigo-900) !important;
}

.title-sub {
    font-size: 0.72rem;
    color: var(--indigo-500) !important;
    -webkit-text-fill-color: var(--indigo-500) !important;
    font-weight: 700;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    margin-top: 3px;
    font-family: 'JetBrains Mono', monospace;
}

/* ===== Risk Banner ===== */
.risk-banner {
    padding: 1.1rem 2rem;
    border-radius: 18px;
    font-size: 1.4rem;
    font-weight: 800;
    text-align: center;
    margin-bottom: 1.2rem;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    font-family: 'Playfair Display', serif;
    position: relative;
    overflow: hidden;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    border: 1px solid rgba(255,255,255,0.3);
}

.risk-banner::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(180deg, rgba(255,255,255,0.14) 0%, transparent 100%);
    pointer-events: none;
}

.risk-banner.critical {
    background: linear-gradient(135deg, #be123c, #9f1239);
    box-shadow: 0 6px 30px rgba(190,18,60,0.30);
}
.risk-banner.high {
    background: linear-gradient(135deg, #c2410c, #9a3412);
    box-shadow: 0 6px 30px rgba(194,65,12,0.28);
}
.risk-banner.medium {
    background: linear-gradient(135deg, var(--amber-600), #b45309);
    box-shadow: 0 6px 30px rgba(217,119,6,0.25);
}
.risk-banner.low {
    background: linear-gradient(135deg, var(--teal-600), #0f766e);
    box-shadow: 0 6px 30px rgba(13,148,136,0.25);
}
.risk-banner.info {
    background: linear-gradient(135deg, var(--indigo-600), var(--indigo-800));
    box-shadow: 0 6px 30px var(--indigo-glow);
}

/* ===== Kill Chain Banner ===== */
.killchain-banner {
    background: var(--coral-100);
    border-left: 4px solid var(--coral-500);
    border-radius: 0 14px 14px 0;
    padding: 0.75rem 1.2rem;
    margin-bottom: 0.5rem;
    color: #9f1239 !important;
    -webkit-text-fill-color: #9f1239 !important;
    font-weight: 700;
    font-size: 0.88rem;
    box-shadow: var(--card-shadow);
    transition: all 0.2s;
}

.killchain-banner:hover {
    background: #ffd7dd;
    border-left-color: var(--coral-600);
    transform: scale(1.01);
}

/* ===== MITRE Tag ===== */
.mitre-tag {
    display: inline-block;
    padding: 3px 11px;
    border-radius: 30px;
    background: var(--indigo-50);
    color: var(--indigo-700) !important;
    -webkit-text-fill-color: var(--indigo-700) !important;
    border: 1px solid var(--indigo-100);
    font-size: 0.72rem;
    font-weight: 700;
    margin: 2px;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.4px;
    transition: 0.2s;
}

.mitre-tag:hover {
    background: var(--indigo-100);
    border-color: var(--indigo-400);
    box-shadow: 0 2px 10px var(--indigo-glow);
}

/* ===== Metric Cards ===== */
[data-testid="metric-container"] {
    background: var(--card-bg) !important;
    backdrop-filter: blur(12px) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: 20px !important;
    padding: 1.2rem !important;
    transition: all 0.2s !important;
    box-shadow: var(--card-shadow) !important;
}

[data-testid="metric-container"]:hover {
    background: var(--card-bg-hover) !important;
    border-color: var(--indigo-400) !important;
    transform: translateY(-3px);
    box-shadow: var(--card-shadow-lg) !important;
}

[data-testid="metric-container"] [data-testid="stMetricLabel"] {
    color: var(--text-muted) !important;
    -webkit-text-fill-color: var(--text-muted) !important;
    font-size: 0.72rem !important;
    font-weight: 700 !important;
    letter-spacing: 1.3px !important;
    text-transform: uppercase !important;
}

[data-testid="metric-container"] [data-testid="stMetricValue"] {
    color: var(--indigo-800) !important;
    -webkit-text-fill-color: var(--indigo-800) !important;
    font-size: 1.9rem !important;
    font-weight: 800 !important;
    font-family: 'Playfair Display', serif !important;
}

[data-testid="metric-container"] [data-testid="stMetricDelta"] {
    color: var(--teal-600) !important;
    -webkit-text-fill-color: var(--teal-600) !important;
    font-weight: 700 !important;
}

/* ===== Tabs ===== */
[data-testid="stTabs"] [role="tablist"] {
    background: rgba(255, 255, 255, 0.65);
    backdrop-filter: blur(10px);
    border-radius: 18px;
    padding: 5px;
    border: 1px solid var(--card-border);
    box-shadow: var(--card-shadow);
}

[data-testid="stTabs"] [role="tab"] {
    border-radius: 14px !important;
    color: var(--text-muted) !important;
    -webkit-text-fill-color: var(--text-muted) !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    padding: 0.5rem 1rem !important;
    transition: all 0.2s !important;
}

[data-testid="stTabs"] [role="tab"]:hover {
    color: var(--indigo-700) !important;
    -webkit-text-fill-color: var(--indigo-700) !important;
    background: var(--indigo-50) !important;
}

[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    background: var(--indigo-600) !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    font-weight: 700 !important;
    box-shadow: 0 4px 14px var(--indigo-glow) !important;
    border: none !important;
}

/* ===== Expanders ===== */
[data-testid="stExpander"] {
    background: var(--card-bg) !important;
    backdrop-filter: blur(10px) !important;
    border: 1px solid var(--card-border) !important;
    border-radius: 18px !important;
    margin-bottom: 0.5rem;
    transition: all 0.2s;
    box-shadow: var(--card-shadow);
}

[data-testid="stExpander"]:hover {
    border-color: var(--indigo-400) !important;
    background: var(--card-bg-hover) !important;
}

[data-testid="stExpander"] summary {
    color: var(--text-secondary) !important;
    -webkit-text-fill-color: var(--text-secondary) !important;
    font-weight: 700 !important;
    padding: 0.5rem;
    font-size: 0.92rem;
}

/* ===== Code Blocks ===== */
[data-testid="stCode"] {
    background: #f5f3ff !important;
    border: 1px solid var(--indigo-100) !important;
    border-radius: 14px !important;
}

[data-testid="stCode"] code, [data-testid="stCode"] * {
    color: var(--indigo-800) !important;
    -webkit-text-fill-color: var(--indigo-800) !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ===== Dataframes ===== */
[data-testid="stDataFrame"] {
    border-radius: 16px;
    overflow: hidden;
    border: 1px solid var(--card-border);
    background: rgba(255,255,255,0.7);
    box-shadow: var(--card-shadow);
}

/* ===== Alerts ===== */
[data-testid="stAlert"] {
    border-radius: 14px !important;
    border: 1px solid var(--card-border) !important;
    background: rgba(255,255,255,0.80) !important;
    color: var(--text-primary) !important;
    -webkit-text-fill-color: var(--text-primary) !important;
}

/* ===== Welcome Cards ===== */
.welcome-card {
    background: var(--card-bg);
    backdrop-filter: blur(12px);
    border: 1px solid var(--card-border);
    border-radius: 22px;
    padding: 1.5rem;
    text-align: center;
    transition: all 0.25s;
    height: 100%;
    box-shadow: var(--card-shadow);
}

.welcome-card:hover {
    border-color: var(--indigo-400);
    background: var(--card-bg-hover);
    transform: translateY(-5px);
    box-shadow: var(--card-shadow-lg);
}

.welcome-card-icon { font-size: 2.3rem; margin-bottom: 0.6rem; }

.welcome-card-title {
    color: var(--indigo-900) !important;
    -webkit-text-fill-color: var(--indigo-900) !important;
    font-weight: 700;
    font-size: 1rem;
    margin-bottom: 0.4rem;
}

.welcome-card-desc {
    color: var(--text-muted) !important;
    -webkit-text-fill-color: var(--text-muted) !important;
    font-size: 0.83rem;
    line-height: 1.6;
}

/* ===== Section Headers ===== */
.section-header {
    color: var(--indigo-800) !important;
    -webkit-text-fill-color: var(--indigo-800) !important;
    font-family: 'Playfair Display', serif;
    font-size: 1.35rem;
    font-weight: 800;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--indigo-100);
    letter-spacing: 0.2px;
}

/* ===== Tool Cards ===== */
.tool-card {
    background: var(--card-bg);
    backdrop-filter: blur(10px);
    border: 1px solid var(--card-border);
    border-radius: 18px;
    padding: 0.8rem 1.2rem;
    margin-bottom: 0.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    transition: all 0.2s;
    box-shadow: var(--card-shadow);
    color: var(--text-secondary) !important;
}

.tool-card:hover {
    border-color: var(--indigo-400);
    background: var(--card-bg-hover);
    transform: translateX(5px);
    box-shadow: var(--card-shadow-lg);
}

/* ===== Risk Item Cards ===== */
.risk-item-card {
    border-radius: 16px;
    color: var(--text-primary) !important;
    -webkit-text-fill-color: var(--text-primary) !important;
    padding: 0.8rem 1.2rem;
    margin-bottom: 0.5rem;
    transition: all 0.2s;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    box-shadow: var(--card-shadow);
}

.risk-item-card:hover {
    border-color: var(--indigo-400);
    background: var(--card-bg-hover);
}

/* ===== Waiting Card ===== */
.waiting-card {
    background: var(--card-bg);
    backdrop-filter: blur(16px);
    border: 1px solid var(--card-border);
    border-radius: 28px;
    padding: 3rem 2rem;
    text-align: center;
    margin: 1.5rem auto;
    max-width: 600px;
    box-shadow: var(--card-shadow-lg);
}

.waiting-title {
    font-family: 'Playfair Display', serif;
    font-size: 2rem;
    font-weight: 800;
    margin-bottom: 0.4rem;
    color: var(--indigo-900) !important;
    -webkit-text-fill-color: var(--indigo-900) !important;
}

.waiting-sub {
    color: var(--text-muted) !important;
    -webkit-text-fill-color: var(--text-muted) !important;
    margin-bottom: 1.8rem;
    font-size: 0.95rem;
}

.step-row {
    display: flex;
    align-items: center;
    gap: 12px;
    background: rgba(255,255,255,0.70);
    border-radius: 14px;
    padding: 0.65rem 1rem;
    margin-bottom: 0.5rem;
    font-size: 0.92rem;
    text-align: left;
    border: 1px solid var(--card-border);
    color: var(--text-primary) !important;
    -webkit-text-fill-color: var(--text-primary) !important;
}

.spulse {
    color: var(--indigo-600) !important;
    -webkit-text-fill-color: var(--indigo-600) !important;
    font-weight: 700;
    animation: pulse 1.2s infinite;
}

.swait {
    color: var(--text-muted) !important;
    -webkit-text-fill-color: var(--text-muted) !important;
}

.sdone {
    color: var(--teal-600) !important;
    -webkit-text-fill-color: var(--teal-600) !important;
    font-weight: 700;
}

@keyframes pulse {
    0%   { opacity: 0.45; }
    50%  { opacity: 1.0;  }
    100% { opacity: 0.45; }
}

.rtimer {
    display: inline-block;
    background: var(--indigo-50);
    border: 1px solid var(--indigo-100);
    border-radius: 40px;
    padding: 0.3rem 1.2rem;
    font-size: 0.9rem;
    margin-top: 1.2rem;
    color: var(--indigo-700) !important;
    -webkit-text-fill-color: var(--indigo-700) !important;
    font-family: 'JetBrains Mono', monospace;
    box-shadow: var(--card-shadow);
    font-weight: 600;
}

/* ===== Scrollbar ===== */
::-webkit-scrollbar { width: 7px; height: 7px; }
::-webkit-scrollbar-track { background: #e8e6f0; }
::-webkit-scrollbar-thumb { background: var(--indigo-400); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--indigo-600); }

/* ===== Divider ===== */
hr {
    border: none;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--indigo-200, #c7d2fe), transparent);
    margin: 1.5rem 0 !important;
}

/* ===== Buttons ===== */
.stButton button {
    background: linear-gradient(135deg, var(--indigo-700), var(--indigo-600)) !important;
    border: none !important;
    border-radius: 14px !important;
    color: #ffffff !important;
    -webkit-text-fill-color: #ffffff !important;
    font-weight: 700 !important;
    font-size: 0.85rem !important;
    padding: 0.6rem 1.3rem !important;
    transition: all 0.2s !important;
    box-shadow: 0 4px 16px var(--indigo-glow) !important;
    letter-spacing: 0.4px;
}

.stButton button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 28px rgba(99,102,241,0.35) !important;
}

/* ===== Select / Input fields ===== */
[data-testid="stSelectbox"] *,
[data-testid="stTextInput"] *,
[data-testid="stNumberInput"] * {
    color: var(--text-primary) !important;
    -webkit-text-fill-color: var(--text-primary) !important;
}

/* ===== Markdown ===== */
.stMarkdown p, .stMarkdown li, .stMarkdown span {
    color: var(--text-primary) !important;
    -webkit-text-fill-color: var(--text-primary) !important;
}

.stMarkdown strong {
    color: var(--indigo-800) !important;
    -webkit-text-fill-color: var(--indigo-800) !important;
    font-weight: 700;
}

.stMarkdown code {
    background: var(--indigo-50) !important;
    color: var(--indigo-700) !important;
    -webkit-text-fill-color: var(--indigo-700) !important;
    border: 1px solid var(--indigo-100);
    border-radius: 5px;
    padding: 1px 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85em;
}

/* ===== Headings ===== */
h1, h2, h3, h4, h5, h6 {
    color: var(--indigo-900) !important;
    -webkit-text-fill-color: var(--indigo-900) !important;
    font-family: 'Playfair Display', serif !important;
}
</style>
"""