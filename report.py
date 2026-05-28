"""
Gera um relatório HTML standalone (sem dependências externas, sem CDN).
Tudo inline pra funcionar offline e ser fácil de mandar pelo Discord.
"""

import os
import html
import base64
import tempfile
from datetime import datetime

try:
    import report_signing
    HAS_SIGNING = True
except ImportError:
    HAS_SIGNING = False


SEVERITY_COLORS = {
    "high":   "#ff4d4f",
    "medium": "#ffb020",
    "low":    "#ffe066",
}

STATUS_BADGE = {
    "clean":      ("LIMPO",     "#3fbf7f"),
    "suspicious": ("SUSPEITO",  "#ff4d4f"),
    "error":      ("ERRO/SKIP", "#888888"),
}


def _escape(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _render_section(finding: dict) -> str:
    name = _escape(finding["name"])
    desc = _escape(finding["description"])
    status = finding["status"]
    badge_text, badge_color = STATUS_BADGE.get(status, ("?", "#888"))
    summary = _escape(finding["summary"])

    rows = []
    for item in finding.get("items", []):
        sev = item.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        conf = item.get("confidence")
        fp_reason = item.get("fp_reason")
        orig_sev = item.get("original_severity")

        # Badge de rebaixamento
        downgrade_badge = ""
        if orig_sev and orig_sev != sev:
            downgrade_badge = (f'<span class="fp-badge" title="{_escape(fp_reason or "")}">'
                                f'↓ era {_escape(orig_sev.upper())}</span>')

        # Confidence bar
        conf_html = ""
        if conf is not None:
            conf_color = "#3fbf7f" if conf >= 70 else ("#ffb020" if conf >= 40 else "#888")
            conf_html = (f'<div class="conf-bar"><div class="conf-fill" '
                          f'style="width:{conf}%; background:{conf_color}"></div>'
                          f'<span class="conf-val">{conf}</span></div>')

        # Detail com fp_reason inline (se houver)
        detail_text = item.get('detail', '')
        if fp_reason:
            detail_text = f"{detail_text}\n[FP-filter: {fp_reason}]"

        rows.append(f"""
        <tr class="row-{sev}">
            <td class="sev"><span class="sev-dot" style="background:{color}"></span>{_escape(sev.upper())}{downgrade_badge}</td>
            <td class="label">{_escape(item.get('label', ''))}</td>
            <td class="detail"><code>{_escape(detail_text)}</code></td>
            <td class="match"><code>{_escape(item.get('matched', ''))}</code></td>
            <td class="conf">{conf_html}</td>
            <td class="ts">{_escape(item.get('timestamp', ''))}</td>
        </tr>""")

    if rows:
        table = f"""
        <table>
            <thead>
                <tr>
                    <th>Severidade</th>
                    <th>Item</th>
                    <th>Detalhe</th>
                    <th>Match</th>
                    <th>Conf.</th>
                    <th>Quando</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        """
    else:
        msg = finding.get("error") or "Nenhum vestígio encontrado nesta categoria."
        table = f'<p class="empty">{_escape(msg)}</p>'

    slug = finding["name"].lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")
    n_items = len(finding.get("items", []))
    # Sections sem hits começam fechadas; com hits, abertas
    open_attr = " open" if n_items > 0 else ""
    return f"""
    <section class="card status-{status}" id="scan-{slug}">
        <details{open_attr}>
            <summary class="card-head">
                <h2>{name}</h2>
                <span class="badge" style="background:{badge_color}">{badge_text}</span>
            </summary>
            <p class="desc">{desc}</p>
            <p class="summary">{summary}</p>
            {table}
        </details>
    </section>
    """


def _render_system(info: dict) -> str:
    rows = "".join(
        f"<tr><th>{_escape(k)}</th><td>{_escape(v)}</td></tr>"
        for k, v in info.items()
    )
    return f"""
    <section class="card sysinfo">
        <h2>Informações do Sistema</h2>
        <table class="sys">{rows}</table>
    </section>
    """


def _render_summary(findings: list[dict], verdict: dict = None) -> str:
    total = sum(len(f["items"]) for f in findings)
    errors = sum(1 for f in findings if f["status"] == "error")

    if verdict is None:
        # Fallback: usa contagem simples se não passou verdict
        high = sum(1 for f in findings for i in f["items"] if i.get("severity") == "high")
        med  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "medium")
        low  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "low")
        verdict = {
            "verdict": "LIMPO" if not (high + med + low) else "REVISAR",
            "color": "#3fbf7f",
            "score": 0,
            "high": high, "medium": med, "low": low,
        }

    score_html = f'<div class="stat"><div class="num" style="color:{verdict["color"]}">{verdict["score"]}</div><div>Score</div></div>'
    recent = verdict.get("most_recent_hit") or "—"

    return f"""
    <section class="card overview">
        <h2>Resumo</h2>
        <div class="big-verdict" style="color:{verdict['color']}">{verdict['verdict']}</div>
        <div class="verdict-sub">Hit mais recente: <code>{_escape(recent)}</code></div>
        <div class="stats">
            <div class="stat"><div class="num" style="color:#ff4d4f">{verdict['high']}</div><div>High</div></div>
            <div class="stat"><div class="num" style="color:#ffb020">{verdict['medium']}</div><div>Medium</div></div>
            <div class="stat"><div class="num" style="color:#ffe066">{verdict['low']}</div><div>Low</div></div>
            {score_html}
            <div class="stat"><div class="num">{total}</div><div>Total</div></div>
            <div class="stat"><div class="num" style="color:#888">{errors}</div><div>Skips/Erros</div></div>
        </div>
    </section>
    """


def _render_fp_stats(fp_stats: dict) -> str:
    """Mostra info do filtro de falso-positivo se rodou."""
    if not fp_stats:
        return ""

    dev_note = ""
    if fp_stats.get("is_dev_env"):
        ev_list = "<br>".join(f"<code>{_escape(p)}</code>" for p in fp_stats["dev_evidence"][:5])
        dev_note = f"""
        <p><strong style="color:#ffb020">⚠ Ambiente de dev detectado.</strong>
        Ferramentas como Cheat Engine, IDA, dnSpy, etc. foram rebaixadas pra LOW
        (uso legítimo provável). Indicadores:</p>
        <div class="dev-evidence">{ev_list}</div>
        """

    return f"""
    <section class="card fp-stats">
        <h2>🛡️ Filtro de Falsos Positivos</h2>
        <p class="desc">Pós-processamento removeu/rebaixou hits prováveis-FP. Use <code>--strict</code> pra desligar.</p>
        <div class="stats">
            <div class="stat"><div class="num">{fp_stats['total_items_in']}</div><div>Hits brutos</div></div>
            <div class="stat"><div class="num" style="color:#3fbf7f">{fp_stats['items_whitelisted']}</div><div>Whitelistados</div></div>
            <div class="stat"><div class="num" style="color:#ffb020">{fp_stats['items_downgraded']}</div><div>Rebaixados</div></div>
            <div class="stat"><div class="num">{fp_stats['total_items_out']}</div><div>Finais</div></div>
        </div>
        {dev_note}
    </section>
    """


CSS = """
* { box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0e0e10; color: #e8e8e8; margin: 0; padding: 24px;
    font-size: 14px;
}
header { text-align: center; margin-bottom: 32px; }
header h1 {
    margin: 0; font-size: 36px; font-weight: 800;
    letter-spacing: 4px;
    background: linear-gradient(90deg, #ff4d4f 0%, #ffb020 50%, #ff4d4f 100%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
}
header .sub { color: #888; margin-top: 6px; }
.card {
    background: #1a1a1d; border: 1px solid #2a2a2e; border-radius: 8px;
    padding: 20px; margin-bottom: 20px;
}
.card-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.card h2 { margin: 0; font-size: 18px; color: #fff; }
.desc { color: #888; margin: 4px 0 8px; font-size: 13px; }
.summary { color: #c0c0c0; margin: 4px 0 12px; font-weight: 600; }
.badge {
    padding: 4px 10px; border-radius: 4px; color: #000;
    font-weight: 700; font-size: 11px; letter-spacing: 1px;
}
.status-suspicious { border-color: #ff4d4f44; }
.status-suspicious h2::before { content: "⚠ "; color: #ff4d4f; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2a2e; vertical-align: top; }
th { background: #232327; color: #aaa; font-weight: 600; text-transform: uppercase; font-size: 11px; }
tr.row-high { background: rgba(255, 77, 79, 0.06); }
tr.row-medium { background: rgba(255, 176, 32, 0.05); }
.sev { white-space: nowrap; font-weight: 700; font-size: 11px; }
.sev-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle;
}
code {
    background: #0a0a0c; padding: 2px 6px; border-radius: 3px;
    color: #ffb020; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px;
    word-break: break-all;
}
.empty { color: #555; font-style: italic; margin: 8px 0; }
.sys th { width: 140px; }
.overview .big-verdict {
    text-align: center; font-size: 28px; font-weight: 800;
    letter-spacing: 2px; margin: 16px 0;
}
.stats { display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; }
.stat {
    background: #0e0e10; border: 1px solid #2a2a2e; border-radius: 6px;
    padding: 14px 24px; min-width: 90px; text-align: center;
}
.stat .num { font-size: 24px; font-weight: 700; }
footer {
    text-align: center; color: #555; margin-top: 32px; font-size: 12px;
}
footer code { background: transparent; color: #888; }
"""


def _render_screenshots(screenshots: dict) -> str:
    """
    `screenshots` = {"desktop": "/path.png", "roblox": "/path.png" or None}
    Embed PNGs em base64 pra ficar tudo num arquivo único.
    """
    if not screenshots:
        return ""

    pieces = []
    label_map = {"desktop": "Desktop primário", "roblox": "Janela do Roblox"}
    for key, path in screenshots.items():
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            continue

        if key.startswith("monitor_"):
            num = key.split("_", 1)[1]
            label = f"Monitor {num}"
        else:
            label = label_map.get(key, key)

        pieces.append(f"""
        <div class="shot">
            <div class="shot-label">{_escape(label)}</div>
            <img src="data:image/png;base64,{b64}" alt="{_escape(key)}" />
        </div>
        """)

    if not pieces:
        return ""

    return f"""
    <section class="card screenshots">
        <h2>Capturas de tela (no momento da SS)</h2>
        <p class="desc">Tiradas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
        Clique pra ampliar.</p>
        <div class="shots">{''.join(pieces)}</div>
    </section>
    """


def _render_timeline(findings: list) -> str:
    """Plota todos os hits com timestamp num gráfico horizontal."""
    items = []
    for f in findings:
        for item in f.get("items", []):
            ts_str = item.get("timestamp", "")
            if not ts_str:
                continue
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            items.append((ts, item, f["name"]))

    if not items:
        return ""

    items.sort(key=lambda x: x[0])
    min_ts = items[0][0]
    max_ts = items[-1][0]
    span = (max_ts - min_ts).total_seconds() or 1

    dots = []
    for ts, item, source in items:
        pos = (ts - min_ts).total_seconds() / span * 100
        sev = item.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        tip = f"{ts.strftime('%Y-%m-%d %H:%M')} · {source}\n{item.get('label', '')}\nmatch: {item.get('matched', '')}"
        dots.append(f'<div class="tl-dot row-{sev}" style="left:{pos:.2f}%; background:{color}" title="{_escape(tip)}"></div>')

    duration = max_ts - min_ts
    duration_str = (
        f"{duration.days}d" if duration.days >= 1
        else f"{duration.seconds // 3600}h {(duration.seconds % 3600) // 60}m"
        if duration.seconds >= 3600
        else f"{duration.seconds // 60}m"
    )

    return f"""
    <section class="card timeline">
        <h2>🕐 Timeline de Atividade ({len(items)} hits)</h2>
        <p class="desc">Cada ponto = 1 hit. Cluster denso = burst suspeito (ex: baixou cheat,
        rodou, deletou tudo em 5 min).</p>
        <div class="tl-range">
            <span>{min_ts.strftime('%Y-%m-%d %H:%M')}</span>
            <span style="color:#888">← {duration_str} →</span>
            <span>{max_ts.strftime('%Y-%m-%d %H:%M')}</span>
        </div>
        <div class="tl-track">{''.join(dots)}</div>
    </section>
    """


def _render_pe_section(findings: list) -> str:
    """Section dedicada a PE analysis dos executáveis encontrados."""
    pe_items = []
    for f in findings:
        for item in f.get("items", []):
            if item.get("pe_info"):
                pe_items.append((f["name"], item))

    if not pe_items:
        return ""

    rows = []
    for source, item in pe_items:
        info = item["pe_info"]
        pe = info.get("pe", {})
        sha = info.get("sha256") or ""
        hash_match = info.get("hash_match")
        packed = pe.get("is_packed")
        packer = pe.get("packer_name")
        compile_ts = pe.get("compile_timestamp", "—")
        machine = pe.get("machine", "?")
        sections = ", ".join(pe.get("sections", [])[:8])

        flags = []
        if hash_match:
            flags.append(f'<span class="pe-flag pe-flag-high">HASH MATCH: {_escape(hash_match)}</span>')
        if packed:
            flags.append(f'<span class="pe-flag pe-flag-high">PACKED ({_escape(packer or "?")})</span>')

        rows.append(f"""
        <tr>
            <td><code>{_escape(os.path.basename(info.get('path', '')))}</code></td>
            <td><code style="font-size:10px">{_escape(sha[:32] + '...' if sha else '?')}</code></td>
            <td>{_escape(compile_ts)}</td>
            <td>{_escape(machine)}</td>
            <td><code style="font-size:11px">{_escape(sections)}</code></td>
            <td>{''.join(flags) or '<span style="color:#888">—</span>'}</td>
        </tr>""")

    return f"""
    <section class="card pe-analysis">
        <h2>🔬 PE Analysis ({len(pe_items)} executáveis)</h2>
        <p class="desc">SHA256 + PE header dos .exe/.dll suspeitos. Packed/compile date recente = red flag.</p>
        <table>
            <thead><tr><th>Arquivo</th><th>SHA256</th><th>Compilado</th><th>Arch</th><th>Sections</th><th>Flags</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


LOGO_SVG = """
<svg viewBox="0 0 64 64" class="brand-logo" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="brandGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="#ff4d4f"/>
            <stop offset="0.5" stop-color="#ff7a3f"/>
            <stop offset="1" stop-color="#ffb020"/>
        </linearGradient>
        <filter id="glow"><feGaussianBlur stdDeviation="1.5"/></filter>
    </defs>
    <path d="M32 4 L56 14 L56 34 Q56 50 32 60 Q8 50 8 34 L8 14 Z"
          fill="url(#brandGrad)" stroke="#0e0e10" stroke-width="0.5"/>
    <circle cx="26" cy="28" r="9" fill="none" stroke="#0e0e10" stroke-width="3"/>
    <line x1="33" y1="35" x2="42" y2="44" stroke="#0e0e10" stroke-width="3" stroke-linecap="round"/>
    <text x="32" y="56" font-size="6" font-weight="800" fill="#0e0e10"
          text-anchor="middle" font-family="Inter, system-ui, sans-serif"
          letter-spacing="1.5">TELADOR</text>
</svg>
"""


def _render_sidebar(findings: list, verdict: dict = None) -> str:
    """Sidebar sticky com TOC e contador por section."""
    links = [
        ('summary', '📊 Resumo', None),
        ('high-confidence', '🎯 Cross-Correlation', None),
        ('fp-stats', '🛡️ FP Filter', None),
        ('timeline', '🕐 Timeline', None),
        ('pe-analysis', '🔬 PE Analysis', None),
        ('charts', '📈 Charts', None),
        ('sysinfo', '💻 Sistema', None),
        ('screenshots', '📸 Screenshots', None),
    ]
    main_links = "".join(
        f'<a href="#{anchor}" class="nav-link">{label}</a>'
        for anchor, label, _ in links
    )

    scanner_links = []
    for f in findings:
        n_items = len(f.get("items", []))
        slug = f["name"].lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")
        if n_items > 0:
            badge = f'<span class="nav-badge">{n_items}</span>'
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-hit">{_escape(f["name"])}{badge}</a>')
        else:
            scanner_links.append(f'<a href="#scan-{slug}" class="nav-link nav-clean">{_escape(f["name"])}</a>')

    score_badge = ""
    if verdict:
        score_badge = f'<div class="nav-score" style="background:{verdict.get("color", "#888")}">' \
                       f'Score {verdict.get("score", 0)}</div>'

    return f"""
    <aside class="sidebar">
        <div class="sidebar-head">
            <div class="brand-row">{LOGO_SVG}<h3>TELADOR BR</h3></div>
            {score_badge}
        </div>
        <nav class="sidebar-nav">
            <div class="nav-group">
                <div class="nav-group-title">Visão geral</div>
                {main_links}
            </div>
            <div class="nav-group">
                <div class="nav-group-title">Scanners ({len(findings)})</div>
                {''.join(scanner_links)}
            </div>
        </nav>
    </aside>
    """


def _render_charts(findings: list, verdict: dict) -> str:
    """Donut do score + bar chart de hits por scanner."""
    if not verdict:
        return ""

    high = verdict.get("high", 0)
    med = verdict.get("medium", 0)
    low = verdict.get("low", 0)
    total = max(1, high + med + low)

    # Donut chart com SVG inline (stroke-dasharray)
    circumference = 2 * 3.14159 * 50  # raio 50
    high_pct = high / total
    med_pct = med / total
    low_pct = low / total
    high_dash = circumference * high_pct
    med_dash = circumference * med_pct
    low_dash = circumference * low_pct

    donut = f"""
    <div class="chart-card">
        <h3>Distribuição de Severidade</h3>
        <svg viewBox="0 0 140 140" class="donut">
            <circle cx="70" cy="70" r="50" fill="none" stroke="#2a2a2e" stroke-width="14"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ff4d4f" stroke-width="14"
                stroke-dasharray="{high_dash:.1f} {circumference:.1f}" transform="rotate(-90 70 70)"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ffb020" stroke-width="14"
                stroke-dasharray="{med_dash:.1f} {circumference:.1f}"
                stroke-dashoffset="{-high_dash:.1f}" transform="rotate(-90 70 70)"/>
            <circle cx="70" cy="70" r="50" fill="none" stroke="#ffe066" stroke-width="14"
                stroke-dasharray="{low_dash:.1f} {circumference:.1f}"
                stroke-dashoffset="{-(high_dash + med_dash):.1f}" transform="rotate(-90 70 70)"/>
            <text x="70" y="68" text-anchor="middle" fill="{verdict.get('color', '#fff')}"
                font-size="22" font-weight="800">{verdict.get('score', 0)}</text>
            <text x="70" y="86" text-anchor="middle" fill="#888" font-size="10">SCORE</text>
        </svg>
        <div class="donut-legend">
            <span><span class="dot" style="background:#ff4d4f"></span> High {high}</span>
            <span><span class="dot" style="background:#ffb020"></span> Medium {med}</span>
            <span><span class="dot" style="background:#ffe066"></span> Low {low}</span>
        </div>
    </div>
    """

    # Bar chart top scanners
    scanner_counts = [(f["name"], len(f.get("items", []))) for f in findings]
    scanner_counts = [(n, c) for n, c in scanner_counts if c > 0]
    scanner_counts.sort(key=lambda x: -x[1])
    top = scanner_counts[:10]
    max_c = max((c for _, c in top), default=1)

    bars = "".join(
        f'<div class="bar-row">'
        f'<span class="bar-label">{_escape(name)}</span>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{(c/max_c)*100:.1f}%"></div></div>'
        f'<span class="bar-count">{c}</span>'
        f'</div>'
        for name, c in top
    )
    bar_chart = f"""
    <div class="chart-card">
        <h3>Hits por Scanner (top {len(top)})</h3>
        <div class="bars">{bars or '<p class="empty">Sem hits</p>'}</div>
    </div>
    """

    return f"""
    <section class="card charts" id="charts">
        <h2>📈 Visualizações</h2>
        <div class="charts-grid">
            {donut}
            {bar_chart}
        </div>
    </section>
    """


def _render_empty_state() -> str:
    """Tela limpa bonita quando 0 hits totais."""
    return """
    <section class="card empty-state">
        <div class="empty-icon">✅</div>
        <h2>Tudo limpo</h2>
        <p>Nenhum hit nas 34 categorias de detecção. Este sistema não apresenta
        indícios de uso de executores Roblox conhecidos, scripts de exploit,
        ou ferramentas de cheating.</p>
        <p class="empty-sub">Lembre-se: detecção heurística pode ter falso-negativo (cheat novo,
        renomeado). Faça SS visual também.</p>
    </section>
    """


def _render_high_confidence(high_confidence: dict) -> str:
    """Section destacada com keywords que aparecem em 3+ fontes."""
    if not high_confidence:
        return ""

    rows = []
    sorted_kws = sorted(
        high_confidence.items(),
        key=lambda kv: -len(kv[1]["sources"]),
    )
    for kw, info in sorted_kws:
        sources_str = ", ".join(_escape(s) for s in info["sources"])
        sev = info.get("worst_severity", "high")
        color = SEVERITY_COLORS.get(sev, "#ff4d4f")
        rows.append(f"""
        <tr>
            <td class="hc-kw"><code style="color:{color}; font-weight:700">{_escape(kw)}</code></td>
            <td class="hc-count">{len(info['sources'])} fontes</td>
            <td class="hc-sources">{sources_str}</td>
        </tr>""")

    return f"""
    <section class="card high-confidence">
        <div class="card-head">
            <h2>🎯 Cross-Correlation — ALTA CONFIANÇA</h2>
            <span class="badge" style="background:#ff4d4f">CHEATER</span>
        </div>
        <p class="desc">Keywords que apareceram em 3+ categorias diferentes. Praticamente
        impossível ser falso positivo — cara tentou apagar mas deixou rastro em várias fontes.</p>
        <table>
            <thead>
                <tr>
                    <th>Keyword</th>
                    <th>Cobertura</th>
                    <th>Onde apareceu</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </section>
    """


def _render_controls() -> str:
    """Barra de search e filtros de severidade."""
    return """
    <section class="card controls">
        <div class="controls-row">
            <input type="text" id="search" placeholder="🔍 Filtrar (ex: krnl, wave, .lua, downloads...)" />
            <div class="filters">
                <button class="filter-btn" data-sev="high"   style="--c:#ff4d4f">High</button>
                <button class="filter-btn" data-sev="medium" style="--c:#ffb020">Medium</button>
                <button class="filter-btn" data-sev="low"    style="--c:#ffe066">Low</button>
                <button id="show-all" class="filter-btn solid">Mostrar tudo</button>
            </div>
        </div>
    </section>
    """


CONTROLS_JS = """
<script>
(function() {
    const search = document.getElementById('search');
    const filters = {high: true, medium: true, low: true};

    function applyAll() {
        document.querySelectorAll('tbody tr').forEach(tr => {
            // Filtro de severidade
            let sevOk = false;
            for (const sev of Object.keys(filters)) {
                if (tr.classList.contains('row-' + sev) && filters[sev]) {
                    sevOk = true; break;
                }
            }
            if (!tr.classList.contains('row-high') && !tr.classList.contains('row-medium') && !tr.classList.contains('row-low')) {
                sevOk = true;  // linhas sem severidade (system info, high-conf) sempre visíveis
            }

            // Filtro de search
            const q = (search.value || '').toLowerCase();
            const textOk = !q || tr.textContent.toLowerCase().includes(q);

            tr.style.display = (sevOk && textOk) ? '' : 'none';
        });

        // Esconde cards que ficaram sem linhas visíveis
        document.querySelectorAll('section.card').forEach(card => {
            const tbody = card.querySelector('tbody');
            if (!tbody) return;
            if (card.classList.contains('overview') || card.classList.contains('sysinfo')
                || card.classList.contains('screenshots') || card.classList.contains('controls')
                || card.classList.contains('high-confidence')) return;
            const visible = Array.from(tbody.querySelectorAll('tr')).some(tr => tr.style.display !== 'none');
            card.style.display = visible ? '' : 'none';
        });
    }

    search.addEventListener('input', applyAll);

    document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {
        btn.addEventListener('click', () => {
            const sev = btn.dataset.sev;
            filters[sev] = !filters[sev];
            btn.classList.toggle('off', !filters[sev]);
            applyAll();
        });
    });

    document.getElementById('show-all').addEventListener('click', () => {
        for (const k of Object.keys(filters)) filters[k] = true;
        document.querySelectorAll('.filter-btn[data-sev]').forEach(b => b.classList.remove('off'));
        search.value = '';
        applyAll();
    });

    // Click pra copiar em code blocks (com toast)
    function showToast(msg) {
        const t = document.createElement('div');
        t.className = 'toast'; t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 1600);
    }
    document.querySelectorAll('code').forEach(c => {
        c.style.cursor = 'pointer';
        c.title = 'Clique pra copiar';
        c.addEventListener('click', (e) => {
            if (e.target.closest('.lightbox')) return;
            navigator.clipboard.writeText(c.textContent).then(() => {
                showToast('✓ Copiado');
            }).catch(() => {});
        });
    });

    // === Lightbox pra screenshots ===
    const lb = document.createElement('div');
    lb.className = 'lightbox';
    lb.innerHTML = '<button class="lightbox-close" aria-label="Fechar">✕</button>' +
                   '<img alt="" />' +
                   '<div class="lightbox-hint">Clique fora ou ESC pra fechar</div>';
    document.body.appendChild(lb);
    const lbImg = lb.querySelector('img');
    const lbClose = lb.querySelector('.lightbox-close');

    function openLightbox(src, alt) {
        lbImg.src = src;
        lbImg.alt = alt || '';
        lb.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    function closeLightbox() {
        lb.classList.remove('active');
        document.body.style.overflow = '';
    }
    lb.addEventListener('click', (e) => {
        if (e.target === lb || e.target === lbClose) closeLightbox();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeLightbox();
    });

    document.querySelectorAll('.screenshots img').forEach(img => {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', () => openLightbox(img.src, img.alt));
    });

    // === Number counter pros stats ===
    function animateNumber(el, target, duration = 1000) {
        const start = performance.now();
        const startVal = 0;
        function tick(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            // easeOutCubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = startVal + (target - startVal) * eased;
            el.textContent = Number.isInteger(target)
                ? Math.round(current)
                : current.toFixed(1);
            if (progress < 1) requestAnimationFrame(tick);
            else el.textContent = target;
        }
        requestAnimationFrame(tick);
    }

    document.querySelectorAll('.stat .num').forEach(el => {
        const raw = el.textContent.trim();
        const target = parseFloat(raw);
        if (isNaN(target)) return;
        // Aguarda animação de entrada terminar antes do counter
        setTimeout(() => animateNumber(el, target, 1200), 300);
    });

    // === Scroll reveal pra sections fora da viewport inicial ===
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animation = 'fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both';
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1, rootMargin: '0px 0px -80px 0px' });

    // Observa cards que entram via scroll (não os primeiros 6 que já animam no load)
    document.querySelectorAll('.main-content > .card').forEach((card, i) => {
        if (i < 6) return;
        card.style.opacity = '0';
        observer.observe(card);
    });

    // === Ripple effect on click pros buttons ===
    document.querySelectorAll('.filter-btn, button').forEach(btn => {
        btn.addEventListener('click', function(e) {
            const ripple = document.createElement('span');
            const rect = this.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            ripple.style.cssText = `
                position: absolute;
                left: ${e.clientX - rect.left - size/2}px;
                top: ${e.clientY - rect.top - size/2}px;
                width: ${size}px; height: ${size}px;
                border-radius: 50%;
                background: rgba(255,255,255,0.3);
                pointer-events: none;
                animation: rippleExpand 0.6s ease-out;
            `;
            this.style.position = this.style.position || 'relative';
            this.style.overflow = 'hidden';
            this.appendChild(ripple);
            setTimeout(() => ripple.remove(), 600);
        });
    });

    // Add ripple keyframe at runtime
    const style = document.createElement('style');
    style.textContent = `@keyframes rippleExpand {
        from { transform: scale(0); opacity: 1; }
        to   { transform: scale(2.5); opacity: 0; }
    }`;
    document.head.appendChild(style);

    // === Verdict big text — efeito de magnet hover ===
    const verdict = document.querySelector('.big-verdict');
    if (verdict) {
        verdict.addEventListener('mousemove', (e) => {
            const rect = verdict.getBoundingClientRect();
            const x = (e.clientX - rect.left - rect.width / 2) / 30;
            const y = (e.clientY - rect.top - rect.height / 2) / 30;
            verdict.style.transform = `translate(${x}px, ${y}px)`;
        });
        verdict.addEventListener('mouseleave', () => {
            verdict.style.transform = '';
        });
    }
})();
</script>
"""


def generate_html_report(findings: list[dict], sys_info: dict,
                          screenshots: dict = None,
                          high_confidence: dict = None,
                          verdict: dict = None,
                          fp_stats: dict = None,
                          output_path: str = None) -> str:
    """Gera HTML e retorna o caminho do arquivo salvo."""
    if output_path is None:
        ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            tempfile.gettempdir(),
            f"telador_relatorio_{ts_tag}.html",
        )

    summary_html = _render_summary(findings, verdict)
    fp_html = _render_fp_stats(fp_stats or {})
    sys_html = _render_system(sys_info)
    screens_html = _render_screenshots(screenshots or {})
    hc_html = _render_high_confidence(high_confidence or {})
    timeline_html = _render_timeline(findings)
    pe_html = _render_pe_section(findings)
    controls_html = _render_controls()
    charts_html = _render_charts(findings, verdict or {})
    sidebar_html = _render_sidebar(findings, verdict)
    sections = "\n".join(_render_section(f) for f in findings)

    # Empty state quando ZERO hits totais
    total_hits = sum(len(f.get("items", [])) for f in findings)
    empty_html = _render_empty_state() if total_hits == 0 else ""

    # Banner com hash do exe
    exe_hash = ""
    if HAS_SIGNING:
        h = report_signing.get_self_hash()
        if h:
            exe_hash = f'<div class="exe-hash">SHA256 do telador: <code>{h}</code></div>'

    extra_css = """
    .screenshots .shots { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; }
    .screenshots .shot { flex: 1 1 480px; max-width: 100%; }
    .screenshots .shot-label { color: #aaa; font-size: 12px; margin-bottom: 4px; }
    .screenshots img {
        max-width: 100%; height: auto; border: 1px solid #2a2a2e;
        border-radius: 6px; cursor: zoom-in; transition: transform .15s;
    }
    .screenshots img:hover { transform: scale(1.02); }

    .high-confidence {
        border: 2px solid #ff4d4f; box-shadow: 0 0 24px rgba(255, 77, 79, 0.2);
    }
    .high-confidence h2 { color: #ff4d4f; }
    .hc-count { color: #ffb020; font-weight: 700; white-space: nowrap; }
    .hc-sources { color: #aaa; font-size: 12px; }

    .controls { position: sticky; top: 0; z-index: 50; }
    .controls-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    .controls input {
        flex: 1; min-width: 260px;
        background: #0e0e10; border: 1px solid #2a2a2e; color: #e8e8e8;
        padding: 10px 14px; border-radius: 6px; font-size: 14px;
        font-family: inherit;
    }
    .controls input:focus { outline: none; border-color: #ff4d4f; }
    .filters { display: flex; gap: 6px; }
    .filter-btn {
        background: var(--c, #444); color: #000; border: none;
        padding: 8px 14px; border-radius: 6px; font-weight: 700;
        cursor: pointer; font-size: 12px; transition: opacity .15s;
    }
    .filter-btn:hover { opacity: 0.85; }
    .filter-btn.off { opacity: 0.3; }
    .filter-btn.solid { background: #2a2a2e; color: #e8e8e8; }

    .fp-badge {
        display: inline-block; margin-left: 6px;
        background: #ffb020; color: #000;
        padding: 1px 6px; border-radius: 3px;
        font-size: 9px; font-weight: 700;
        cursor: help;
    }
    .conf-bar {
        position: relative; width: 60px; height: 14px;
        background: #0a0a0c; border-radius: 3px; overflow: hidden;
    }
    .conf-fill {
        height: 100%; transition: width .3s;
    }
    .conf-val {
        position: absolute; top: 0; left: 0; width: 100%;
        text-align: center; font-size: 10px; line-height: 14px;
        color: #fff; font-weight: 700;
        text-shadow: 0 0 2px #000;
    }
    .verdict-sub {
        text-align: center; color: #888; margin: -8px 0 16px;
        font-size: 13px;
    }
    .fp-stats { border-left: 4px solid #3fbf7f; }
    .dev-evidence {
        background: #0a0a0c; padding: 10px; border-radius: 6px;
        margin-top: 8px; font-size: 12px;
    }
    .timeline .tl-range {
        display: flex; justify-content: space-between;
        color: #aaa; font-size: 12px; margin: 8px 0 4px;
    }
    .timeline .tl-track {
        position: relative; height: 48px;
        background: linear-gradient(90deg, #1a1a1d, #2a2a2e, #1a1a1d);
        border-radius: 24px; margin: 6px 0 12px;
        border: 1px solid #2a2a2e;
    }
    .timeline .tl-dot {
        position: absolute; top: 50%; transform: translate(-50%, -50%);
        width: 12px; height: 12px; border-radius: 50%;
        cursor: help; box-shadow: 0 0 8px currentColor;
        transition: transform .15s, box-shadow .15s;
    }
    .timeline .tl-dot:hover {
        transform: translate(-50%, -50%) scale(2);
        z-index: 10;
        box-shadow: 0 0 16px currentColor;
    }
    .pe-analysis { border-left: 4px solid #ffb020; }
    .pe-flag {
        display: inline-block; padding: 2px 8px; border-radius: 3px;
        font-size: 10px; font-weight: 700; margin-right: 4px;
    }
    .pe-flag-high { background: #ff4d4f; color: #000; }
    .exe-hash {
        text-align: center; color: #666; font-size: 11px;
        margin-top: 24px; padding: 12px; background: #0a0a0c;
        border-radius: 6px;
    }
    .exe-hash code { color: #888; word-break: break-all; }

    /* === Layout com sidebar === */
    body { display: flex; padding: 0; min-height: 100vh; }
    .sidebar {
        position: sticky; top: 0; height: 100vh;
        width: 260px; flex-shrink: 0;
        background: #08080a; border-right: 1px solid #1f1f23;
        padding: 20px 0; overflow-y: auto;
    }
    .sidebar-head {
        padding: 0 20px 20px; border-bottom: 1px solid #1f1f23;
    }
    .sidebar-head h3 {
        margin: 0 0 12px; font-size: 18px; letter-spacing: 2px;
        background: linear-gradient(90deg, #ff4d4f, #ffb020);
        -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .nav-score {
        display: inline-block; padding: 6px 12px;
        color: #000; font-weight: 800; font-size: 12px;
        border-radius: 4px; letter-spacing: 1px;
    }
    .sidebar-nav { padding: 12px 0; }
    .nav-group { margin-bottom: 20px; }
    .nav-group-title {
        padding: 8px 20px; color: #555; font-size: 10px;
        text-transform: uppercase; letter-spacing: 2px; font-weight: 700;
    }
    .nav-link {
        display: flex; justify-content: space-between; align-items: center;
        padding: 8px 20px; color: #aaa; text-decoration: none;
        font-size: 13px; transition: background .1s, color .1s;
        border-left: 3px solid transparent;
    }
    .nav-link:hover { background: #131316; color: #fff; border-left-color: #ff4d4f; }
    .nav-link.nav-hit { color: #e8e8e8; font-weight: 600; }
    .nav-link.nav-clean { color: #555; }
    .nav-badge {
        background: #ff4d4f; color: #000; padding: 2px 8px;
        border-radius: 10px; font-size: 11px; font-weight: 700;
    }
    .main-content {
        flex: 1; padding: 24px; max-width: calc(100% - 260px);
        scroll-padding-top: 20px;
    }
    .page-header {
        margin-bottom: 24px; padding-bottom: 16px;
        border-bottom: 1px solid #1f1f23;
    }
    .page-header h1 {
        margin: 0; font-size: 32px; font-weight: 800; letter-spacing: 3px;
        background: linear-gradient(90deg, #ff4d4f 0%, #ffb020 50%, #ff4d4f 100%);
        -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .page-header .sub { color: #666; margin-top: 4px; font-size: 13px; }
    .page-footer {
        margin-top: 32px; padding: 20px; border-top: 1px solid #1f1f23;
        color: #555; font-size: 12px; text-align: center;
    }

    /* === Collapsible sections === */
    details > summary {
        cursor: pointer; list-style: none; user-select: none;
    }
    details > summary::-webkit-details-marker { display: none; }
    details > summary::before {
        content: "▶"; display: inline-block; margin-right: 10px;
        color: #555; font-size: 10px;
        transition: transform .15s;
    }
    details[open] > summary::before { transform: rotate(90deg); }
    details > summary:hover h2 { color: #ff4d4f; }

    /* === Charts === */
    .charts-grid {
        display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
    }
    @media (max-width: 900px) {
        .charts-grid { grid-template-columns: 1fr; }
    }
    .chart-card {
        background: #0e0e10; border: 1px solid #2a2a2e;
        border-radius: 8px; padding: 16px;
    }
    .chart-card h3 {
        margin: 0 0 12px; font-size: 13px; color: #aaa;
        text-transform: uppercase; letter-spacing: 1px;
    }
    .donut { width: 100%; max-width: 220px; height: auto; display: block; margin: 0 auto; }
    .donut-legend {
        display: flex; justify-content: center; gap: 16px;
        font-size: 12px; color: #aaa; margin-top: 12px; flex-wrap: wrap;
    }
    .donut-legend .dot {
        display: inline-block; width: 8px; height: 8px; border-radius: 50%;
        margin-right: 6px; vertical-align: middle;
    }
    .bars { display: flex; flex-direction: column; gap: 8px; }
    .bar-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
    .bar-label {
        flex: 0 0 35%; color: #ccc; text-align: right; overflow: hidden;
        text-overflow: ellipsis; white-space: nowrap;
    }
    .bar-track {
        flex: 1; height: 16px; background: #0a0a0c; border-radius: 3px;
        overflow: hidden;
    }
    .bar-fill {
        height: 100%; background: linear-gradient(90deg, #ff4d4f, #ffb020);
        transition: width .5s;
    }
    .bar-count {
        flex: 0 0 30px; text-align: left; color: #ffb020; font-weight: 700;
    }

    /* === Empty state === */
    .empty-state {
        text-align: center; padding: 40px 20px;
        border: 2px dashed #3fbf7f44;
    }
    .empty-icon { font-size: 64px; margin-bottom: 16px; }
    .empty-state h2 {
        color: #3fbf7f; margin: 0 0 12px;
        font-size: 28px; letter-spacing: 1px;
    }
    .empty-state p { color: #aaa; max-width: 540px; margin: 0 auto 8px; }
    .empty-state .empty-sub { color: #666; font-size: 12px; margin-top: 16px; }

    /* === Print === */
    @media print {
        body { background: white; color: black; display: block; }
        .sidebar, .controls { display: none !important; }
        .main-content { max-width: 100%; padding: 0; }
        .card { break-inside: avoid; border-color: #ccc; background: white; }
        .card h2 { color: black; }
        code { color: #c5780b; background: #f5f5f5; }
        details { open: true; }
        details > summary::before { display: none; }
    }

    /* === Mobile === */
    @media (max-width: 700px) {
        body { flex-direction: column; }
        .sidebar { position: relative; width: 100%; height: auto; }
        .main-content { max-width: 100%; }
    }

    /* === Custom scrollbar === */
    * { scrollbar-width: thin; scrollbar-color: #ff4d4f #0a0a0c; }
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: #0a0a0c; }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #ff4d4f, #ffb020);
        border-radius: 10px; border: 2px solid #0a0a0c;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #ff6668, #ffc040);
    }
    ::-webkit-scrollbar-corner { background: #0a0a0c; }
    .sidebar::-webkit-scrollbar { width: 6px; }
    .sidebar::-webkit-scrollbar-thumb { background: #ff4d4f55; border: none; }

    /* === Espaçamento refinado === */
    body {
        font-size: 14px; line-height: 1.5;
    }
    .main-content {
        padding: 32px 40px 24px;
        max-width: calc(100% - 260px);
    }
    .card {
        padding: 24px 28px; margin-bottom: 16px;
        border-radius: 10px;
    }
    .card h2 { font-size: 17px; margin: 0; line-height: 1.4; }
    .card .desc {
        margin: 8px 0 12px; font-size: 13px; line-height: 1.55;
    }
    .card .summary { margin: 8px 0 16px; font-size: 13px; }
    .card-head { padding: 4px 0; gap: 16px; }
    details > summary { padding: 4px 0; }
    details[open] > summary { margin-bottom: 4px; }
    table { margin-top: 4px; }
    th, td { padding: 10px 12px; }
    .stats { gap: 12px; margin: 8px 0 4px; }
    .stat { padding: 16px 24px; min-width: 96px; }
    .stat .num { font-size: 26px; line-height: 1.2; margin-bottom: 4px; }
    .stat > div:last-child { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
    .page-header { margin-bottom: 20px; padding-bottom: 16px; }
    .page-header h1 { font-size: 28px; letter-spacing: 4px; }

    /* Sidebar refinements */
    .sidebar { padding: 24px 0 32px; }
    .sidebar-head { padding: 0 24px 20px; }
    .sidebar-head h3 { font-size: 17px; letter-spacing: 3px; margin: 0 0 14px; }
    .sidebar-nav { padding: 16px 0 8px; }
    .nav-group { margin-bottom: 24px; }
    .nav-group-title {
        padding: 10px 24px; font-size: 10px; letter-spacing: 2px;
    }
    .nav-link {
        padding: 9px 24px; font-size: 13px; line-height: 1.4;
        margin: 1px 0;
    }
    .nav-badge { padding: 2px 9px; font-size: 10px; margin-left: 8px; }

    /* Charts spacing */
    .charts-grid { gap: 16px; margin-top: 8px; }
    .chart-card { padding: 20px; }
    .chart-card h3 { margin: 0 0 16px; font-size: 12px; letter-spacing: 1.5px; }
    .donut-legend { margin-top: 16px; gap: 20px; }
    .bars { gap: 10px; }
    .bar-row { font-size: 12px; }
    .bar-label { padding-right: 4px; }
    .bar-track { height: 14px; border-radius: 4px; }

    /* Timeline refinement */
    .timeline .tl-range { margin: 12px 0 6px; padding: 0 4px; }
    .timeline .tl-track { margin: 8px 0 16px; height: 44px; }

    /* Sections code refinement */
    code { padding: 2px 7px; font-size: 12px; }
    .empty { padding: 12px 0; font-size: 13px; }

    /* FP-stats and high-confidence padding */
    .fp-stats, .high-confidence { padding: 24px 28px; }
    .verdict-sub { margin: -4px 0 18px; }
    .overview .big-verdict { font-size: 32px; margin: 18px 0 10px; }

    /* ================================================================
       === 10/10 PASS: design tokens, typography, animations, lightbox
       ================================================================ */

    :root {
        /* Spacing scale (4-8-12-16-24-32-48-64) */
        --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px;
        --s-6: 24px; --s-8: 32px; --s-12: 48px; --s-16: 64px;

        /* Color tokens */
        --c-red: #ff4d4f;
        --c-red-soft: rgba(255, 77, 79, 0.08);
        --c-orange: #ffb020;
        --c-orange-soft: rgba(255, 176, 32, 0.07);
        --c-yellow: #ffe066;
        --c-green: #3fbf7f;
        --c-green-soft: rgba(63, 191, 127, 0.08);

        /* Neutral scale */
        --c-bg-0: #08080a;
        --c-bg-1: #0e0e10;
        --c-bg-2: #16161a;
        --c-bg-3: #1a1a1d;
        --c-bg-4: #232327;
        --c-border: #1f1f23;
        --c-border-soft: #15151a;

        /* Text scale */
        --c-text: #f0f0f2;
        --c-text-mute: #aaa;
        --c-text-soft: #777;
        --c-text-faint: #555;

        /* Motion */
        --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
        --ease: cubic-bezier(0.4, 0, 0.2, 1);
    }

    /* Typography upgrade — Segoe UI Variable (Win11) cai bonito */
    body, .nav-link, .sidebar-head h3, .page-header h1, button, input {
        font-family: 'Inter', 'Segoe UI Variable', -apple-system,
                     BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        font-feature-settings: "cv02", "cv03", "cv04", "cv11", "ss01";
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        text-rendering: optimizeLegibility;
    }
    code, .conf-val, pre {
        font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas',
                     'SF Mono', monospace;
        font-feature-settings: "calt", "liga", "ss01", "ss02";
    }
    body { color: var(--c-text); letter-spacing: -0.005em; }
    h1, h2, h3 { letter-spacing: -0.015em; font-weight: 700; }

    /* === Animations === */
    @keyframes fadeUp {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(255, 77, 79, 0.5); }
        50%      { box-shadow: 0 0 0 14px rgba(255, 77, 79, 0); }
    }
    @keyframes shimmer {
        0%   { background-position: -200% 0; }
        100% { background-position: 200% 0; }
    }
    @keyframes scaleIn {
        from { opacity: 0; transform: scale(0.96); }
        to   { opacity: 1; transform: scale(1); }
    }

    /* Apply stagger to cards */
    .card {
        animation: fadeUp 0.5s var(--ease-out) both;
        transition: border-color 0.2s var(--ease), transform 0.15s var(--ease);
    }
    .card:nth-child(1) { animation-delay: 0ms; }
    .card:nth-child(2) { animation-delay: 40ms; }
    .card:nth-child(3) { animation-delay: 80ms; }
    .card:nth-child(4) { animation-delay: 120ms; }
    .card:nth-child(5) { animation-delay: 160ms; }
    .card:nth-child(6) { animation-delay: 200ms; }
    .card:nth-child(7) { animation-delay: 240ms; }
    .card:nth-child(n+8) { animation-delay: 280ms; }
    .sidebar { animation: fadeUp 0.4s var(--ease-out) both; }
    .page-header h1 {
        background-size: 200% 100%;
        animation: shimmer 8s linear infinite;
    }

    /* Big verdict pulse for CHEATER */
    .big-verdict {
        animation: scaleIn 0.6s var(--ease-out) both;
        text-shadow: 0 0 24px currentColor;
    }

    /* === Hovers refined === */
    .card:hover {
        transform: translateY(-1px);
        border-color: var(--c-border);
    }
    .stat {
        transition: transform 0.15s var(--ease), background 0.15s var(--ease);
    }
    .stat:hover {
        transform: translateY(-2px);
        background: var(--c-bg-3) !important;
    }
    code {
        transition: background 0.15s var(--ease), color 0.15s var(--ease);
    }
    code:hover { background: var(--c-bg-4); color: #ffd680; }

    /* === Better neutrals on existing components === */
    body { background: var(--c-bg-1); }
    .sidebar { background: var(--c-bg-0); border-color: var(--c-border); }
    .card { background: var(--c-bg-3); border-color: var(--c-border); }
    .chart-card, .stat, code { background: var(--c-bg-1); }
    .stat { border-color: var(--c-border); }
    th { background: var(--c-bg-4); color: var(--c-text-mute); }
    .controls input { background: var(--c-bg-1); border-color: var(--c-border); }

    /* === Lightbox for screenshots === */
    .lightbox {
        position: fixed; inset: 0; z-index: 1000;
        background: rgba(0, 0, 0, 0.92);
        backdrop-filter: blur(8px);
        display: none; align-items: center; justify-content: center;
        padding: 32px;
        animation: scaleIn 0.2s var(--ease-out);
        cursor: zoom-out;
    }
    .lightbox.active { display: flex; }
    .lightbox img {
        max-width: 100%; max-height: 100%;
        object-fit: contain;
        border-radius: 8px;
        box-shadow: 0 24px 72px rgba(0, 0, 0, 0.6);
        cursor: default;
    }
    .lightbox-close {
        position: absolute; top: 24px; right: 24px;
        background: rgba(255, 255, 255, 0.1); color: #fff;
        border: none; width: 40px; height: 40px;
        border-radius: 50%; cursor: pointer;
        font-size: 20px;
        transition: background 0.15s;
    }
    .lightbox-close:hover { background: rgba(255, 255, 255, 0.2); }
    .lightbox-hint {
        position: absolute; bottom: 24px;
        color: var(--c-text-soft); font-size: 12px;
        letter-spacing: 1px;
    }

    /* Toast for copy feedback */
    .toast {
        position: fixed; bottom: 24px; right: 24px; z-index: 999;
        background: var(--c-green); color: #000;
        padding: 12px 20px; border-radius: 8px;
        font-weight: 600; font-size: 13px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        animation: fadeUp 0.3s var(--ease-out);
    }

    /* Focus visible (a11y) */
    *:focus-visible {
        outline: 2px solid var(--c-red);
        outline-offset: 2px;
        border-radius: 4px;
    }
    *:focus:not(:focus-visible) { outline: none; }

    /* Selection */
    ::selection { background: var(--c-red); color: #000; }

    /* Reduced motion */
    @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
            animation-duration: 0.01ms !important;
            transition-duration: 0.01ms !important;
        }
    }

    /* Brand logo */
    .brand-row {
        display: flex; align-items: center; gap: 12px;
        margin-bottom: 14px;
    }
    .brand-logo {
        width: 40px; height: 40px; flex-shrink: 0;
        filter: drop-shadow(0 2px 8px rgba(255, 77, 79, 0.4));
        animation: scaleIn 0.5s var(--ease-out) both, logoFloat 6s ease-in-out infinite;
        transition: transform 0.3s var(--ease-out);
    }
    .brand-row:hover .brand-logo {
        transform: rotate(-8deg) scale(1.1);
        filter: drop-shadow(0 4px 16px rgba(255, 77, 79, 0.7));
    }
    .brand-row h3 { margin: 0; line-height: 1; }

    /* ================================================================
       === PREMIUM ANIMATION PASS — make it feel alive
       ================================================================ */

    @keyframes logoFloat {
        0%, 100% { transform: translateY(0); }
        50%      { transform: translateY(-3px); }
    }
    @keyframes slideRight {
        from { opacity: 0; transform: translateX(-20px); }
        to   { opacity: 1; transform: translateX(0); }
    }
    @keyframes slideLeft {
        from { opacity: 0; transform: translateX(20px); }
        to   { opacity: 1; transform: translateX(0); }
    }
    @keyframes glowPulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(255, 77, 79, 0); }
        50%      { box-shadow: 0 0 0 12px rgba(255, 77, 79, 0.15); }
    }
    @keyframes drawCircle {
        from { stroke-dashoffset: 314; }
        to   { stroke-dashoffset: var(--final-offset, 0); }
    }
    @keyframes barGrow {
        from { width: 0; }
        to   { width: var(--final-width, 100%); }
    }
    @keyframes countUp {
        from { opacity: 0; transform: translateY(8px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes gradientShift {
        0%   { background-position: 0% 50%; }
        50%  { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    @keyframes sweep {
        0%   { left: -100%; }
        100% { left: 100%; }
    }
    @keyframes statPop {
        0%   { transform: scale(0.8); opacity: 0; }
        50%  { transform: scale(1.05); }
        100% { transform: scale(1); opacity: 1; }
    }
    @keyframes verdictReveal {
        0%   { opacity: 0; transform: scale(0.7) rotateX(-30deg); filter: blur(4px); }
        60%  { transform: scale(1.05) rotateX(0); filter: blur(0); }
        100% { opacity: 1; transform: scale(1) rotateX(0); }
    }
    @keyframes shimmerBar {
        0%   { background-position: -1000px 0; }
        100% { background-position: 1000px 0; }
    }
    @keyframes hoverFloat {
        0%, 100% { transform: translateY(0); }
        50%      { transform: translateY(-4px); }
    }

    /* === Sidebar slide-in === */
    .sidebar {
        animation: slideRight 0.5s var(--ease-out) both;
    }
    .sidebar-head { animation: countUp 0.6s 0.1s var(--ease-out) both; }
    .nav-group { animation: countUp 0.5s var(--ease-out) both; }
    .nav-group:nth-child(1) { animation-delay: 0.2s; }
    .nav-group:nth-child(2) { animation-delay: 0.3s; }
    .nav-link {
        position: relative; overflow: hidden;
    }
    .nav-link::after {
        content: ''; position: absolute; top: 0; left: -100%;
        width: 50%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 77, 79, 0.08), transparent);
        transition: left 0.5s var(--ease-out);
    }
    .nav-link:hover::after { left: 200%; }
    .nav-link.nav-hit .nav-badge {
        animation: glowPulse 2.5s ease-in-out infinite;
    }

    /* === Score badge breath === */
    .nav-score {
        animation: scaleIn 0.6s 0.4s var(--ease-out) both, glowPulse 3s 1s ease-in-out infinite;
    }

    /* === Stats premium animation === */
    .stat {
        animation: statPop 0.5s var(--ease-out) both;
        position: relative; overflow: hidden;
    }
    .stat:nth-child(1) { animation-delay: 50ms; }
    .stat:nth-child(2) { animation-delay: 100ms; }
    .stat:nth-child(3) { animation-delay: 150ms; }
    .stat:nth-child(4) { animation-delay: 200ms; }
    .stat:nth-child(5) { animation-delay: 250ms; }
    .stat:nth-child(6) { animation-delay: 300ms; }
    .stat::before {
        content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
        background: linear-gradient(90deg, transparent,
                    rgba(255, 255, 255, 0.04), transparent);
        transition: left 0.7s var(--ease-out);
    }
    .stat:hover::before { left: 100%; }
    .stat .num {
        animation: countUp 0.7s 0.3s var(--ease-out) both;
        background: linear-gradient(135deg, currentColor, currentColor);
        -webkit-background-clip: text; background-clip: text;
    }

    /* === Verdict 3D reveal === */
    .big-verdict {
        animation: verdictReveal 0.9s var(--ease-out) both;
        perspective: 600px;
        position: relative;
    }
    .big-verdict::after {
        content: ''; position: absolute; inset: -8px;
        background: radial-gradient(circle at center, currentColor 0%, transparent 60%);
        opacity: 0.15; z-index: -1;
        filter: blur(20px);
    }

    /* === Cards premium === */
    .card {
        position: relative; overflow: hidden;
        backdrop-filter: blur(10px);
        transition: transform 0.25s var(--ease-out),
                    border-color 0.25s var(--ease),
                    box-shadow 0.25s var(--ease);
    }
    .card::before {
        content: ''; position: absolute; top: 0; left: 0;
        width: 100%; height: 1px;
        background: linear-gradient(90deg, transparent,
                    rgba(255, 77, 79, 0.4), transparent);
        opacity: 0; transition: opacity 0.3s;
    }
    .card:hover {
        transform: translateY(-3px);
        box-shadow: 0 16px 40px rgba(0, 0, 0, 0.3),
                    0 0 0 1px rgba(255, 77, 79, 0.15);
    }
    .card:hover::before { opacity: 1; }
    .card.status-suspicious {
        border-color: rgba(255, 77, 79, 0.25);
    }
    .card.status-suspicious::after {
        content: ''; position: absolute; top: 0; right: 0;
        width: 4px; height: 100%;
        background: linear-gradient(180deg, var(--c-red), var(--c-orange));
        opacity: 0.8;
    }

    /* === Bars animadas === */
    .bar-fill {
        animation: barGrow 1.2s 0.3s var(--ease-out) both;
        background: linear-gradient(90deg, var(--c-red), var(--c-orange), var(--c-yellow));
        background-size: 200% 100%;
        animation: barGrow 1.2s 0.3s var(--ease-out) both,
                   gradientShift 4s ease-in-out infinite;
        position: relative; overflow: hidden;
    }
    .bar-fill::after {
        content: ''; position: absolute; top: 0; left: 0;
        width: 100%; height: 100%;
        background: linear-gradient(90deg, transparent,
                    rgba(255, 255, 255, 0.3), transparent);
        background-size: 200% 100%;
        animation: shimmerBar 3s infinite;
    }

    /* === Donut chart drawing animation === */
    .donut circle:not(:first-child) {
        stroke-dasharray: 0 314;
        animation: drawCircle 1.5s 0.2s var(--ease-out) both;
        transform-origin: center;
    }
    .donut text {
        animation: countUp 0.8s 1s var(--ease-out) both;
    }

    /* === Timeline dots pop in === */
    .timeline .tl-dot {
        animation: statPop 0.4s var(--ease-out) both,
                   glowPulse 3s ease-in-out infinite;
        transition: transform 0.2s var(--ease-out), box-shadow 0.2s;
    }
    .timeline .tl-dot:nth-child(odd)  { animation-delay: calc(var(--i, 0) * 30ms); }
    .timeline .tl-dot:hover {
        transform: translate(-50%, -50%) scale(2.5);
        z-index: 50;
        box-shadow: 0 0 24px currentColor;
    }

    /* === Empty state celebration === */
    .empty-state .empty-icon {
        animation: scaleIn 0.8s var(--ease-out) both,
                   hoverFloat 3s 1s ease-in-out infinite;
        display: inline-block;
    }
    .empty-state h2 {
        animation: countUp 0.6s 0.2s var(--ease-out) both;
    }
    .empty-state p {
        animation: countUp 0.6s 0.4s var(--ease-out) both;
    }

    /* === Header gradient sweep === */
    .page-header h1 {
        background: linear-gradient(90deg,
            #ff4d4f 0%, #ff7a3f 25%, #ffb020 50%,
            #ff7a3f 75%, #ff4d4f 100%);
        background-size: 300% 100%;
        -webkit-background-clip: text; background-clip: text;
        color: transparent;
        animation: gradientShift 6s ease-in-out infinite,
                   countUp 0.7s var(--ease-out) both;
    }

    /* === Charts entry === */
    .chart-card {
        animation: scaleIn 0.6s var(--ease-out) both;
        transition: transform 0.3s var(--ease-out),
                    box-shadow 0.3s;
        position: relative;
    }
    .chart-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 16px 32px rgba(0, 0, 0, 0.25);
    }
    .chart-card:nth-child(1) { animation-delay: 0.1s; }
    .chart-card:nth-child(2) { animation-delay: 0.2s; }

    /* === Filter buttons === */
    .filter-btn {
        position: relative; overflow: hidden;
        transition: transform 0.15s var(--ease-out),
                    box-shadow 0.15s, opacity 0.15s;
    }
    .filter-btn::before {
        content: ''; position: absolute; inset: 0;
        background: rgba(255, 255, 255, 0.15);
        opacity: 0; transition: opacity 0.15s;
    }
    .filter-btn:hover {
        transform: translateY(-1px) scale(1.02);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    .filter-btn:hover::before { opacity: 1; }
    .filter-btn:active { transform: translateY(0) scale(0.98); }

    /* === Search input glow on focus === */
    .controls input {
        transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }
    .controls input:focus {
        border-color: var(--c-red);
        box-shadow: 0 0 0 4px rgba(255, 77, 79, 0.15);
        background: var(--c-bg-2);
    }

    /* === Severity row hover === */
    tbody tr {
        transition: background 0.2s var(--ease-out);
    }
    tbody tr:hover {
        background: rgba(255, 77, 79, 0.05);
    }
    tbody tr.row-high { animation: countUp 0.4s var(--ease-out) both; }
    tbody tr.row-high:hover {
        background: rgba(255, 77, 79, 0.12);
    }

    /* === Sev dot pulse for HIGH === */
    .row-high .sev-dot {
        animation: glowPulse 2s ease-in-out infinite;
    }

    /* === Code copy ripple === */
    code {
        position: relative; overflow: hidden;
        transition: background 0.15s, color 0.15s, transform 0.15s;
    }
    code:active { transform: scale(0.97); }

    /* === Lightbox more dramatic === */
    .lightbox {
        animation: scaleIn 0.25s var(--ease-out);
    }
    .lightbox img {
        animation: verdictReveal 0.4s 0.05s var(--ease-out) both;
        transition: transform 0.3s var(--ease-out);
    }
    .lightbox img:hover {
        transform: scale(1.02);
    }
    .lightbox-close {
        transition: background 0.2s, transform 0.2s;
    }
    .lightbox-close:hover {
        background: var(--c-red) !important;
        color: #000 !important;
        transform: rotate(90deg) scale(1.1);
    }

    /* === Toast premium === */
    .toast {
        animation: scaleIn 0.3s var(--ease-out) both;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.5),
                    0 0 0 1px rgba(63, 191, 127, 0.4);
        backdrop-filter: blur(8px);
    }

    /* === Sidebar nav stagger === */
    .nav-link {
        animation: slideRight 0.35s var(--ease-out) both;
    }
    .nav-link:nth-child(1)  { animation-delay: 0.25s; }
    .nav-link:nth-child(2)  { animation-delay: 0.28s; }
    .nav-link:nth-child(3)  { animation-delay: 0.31s; }
    .nav-link:nth-child(4)  { animation-delay: 0.34s; }
    .nav-link:nth-child(5)  { animation-delay: 0.37s; }
    .nav-link:nth-child(6)  { animation-delay: 0.40s; }
    .nav-link:nth-child(7)  { animation-delay: 0.43s; }
    .nav-link:nth-child(8)  { animation-delay: 0.46s; }
    .nav-link:nth-child(9)  { animation-delay: 0.49s; }
    .nav-link:nth-child(n+10) { animation-delay: 0.52s; }

    /* === Smooth scroll === */
    html { scroll-behavior: smooth; }

    /* === Better borders w/ gradient on hover === */
    .high-confidence {
        position: relative;
    }
    .high-confidence::before {
        content: ''; position: absolute; inset: 0;
        border-radius: 10px;
        padding: 2px;
        background: linear-gradient(135deg, var(--c-red), var(--c-orange));
        -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        -webkit-mask-composite: xor; mask-composite: exclude;
        pointer-events: none;
        animation: gradientShift 4s ease-in-out infinite;
    }

    /* === Details summary smooth === */
    details > summary::before {
        transition: transform 0.25s var(--ease-out), color 0.2s;
    }
    details[open] > summary::before {
        color: var(--c-red);
    }
    details summary h2 {
        transition: color 0.2s, transform 0.2s var(--ease-out);
    }
    details summary:hover h2 {
        transform: translateX(2px);
        color: var(--c-orange);
    }

    /* === FP badge bounce === */
    .fp-badge {
        animation: statPop 0.4s var(--ease-out) both;
        animation-delay: 0.6s;
        cursor: help;
        transition: transform 0.15s;
    }
    .fp-badge:hover { transform: scale(1.1); }
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório do Telador — {sys_info.get('host', '')}</title>
    <style>{CSS}{extra_css}</style>
</head>
<body>
    {sidebar_html}
    <main class="main-content">
    <header class="page-header">
        <h1>TELADOR BR</h1>
        <div class="sub">Relatório gerado em {sys_info.get('scan_time', '')}</div>
    </header>
    <span id="summary"></span>{summary_html}
    {empty_html}
    <span id="high-confidence"></span>{hc_html}
    <span id="fp-stats"></span>{fp_html}
    <span id="timeline"></span>{timeline_html}
    <span id="pe-analysis"></span>{pe_html}
    {charts_html}
    <span id="sysinfo"></span>{sys_html}
    <span id="screenshots"></span>{screens_html}
    {controls_html}
    {sections}
    {exe_hash}
    <footer class="page-footer">
        Resultado é heurístico (baseado em nomes/locais conhecidos).
        Pode haver falso positivo (ex.: alguém pesquisou sobre o tema) ou falso negativo (cheat com nome trocado).
        Conduza a tela completa e verifique manualmente os pontos suspeitos.
    </footer>
    </main>
    {CONTROLS_JS}
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    return output_path
