"""
Gera um relatório HTML standalone (sem dependências externas, sem CDN).
Tudo inline pra funcionar offline e ser fácil de mandar pelo Discord.
"""

import os
import html
import base64
import tempfile
from datetime import datetime


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
        rows.append(f"""
        <tr class="row-{sev}">
            <td class="sev"><span class="sev-dot" style="background:{color}"></span>{_escape(sev.upper())}</td>
            <td class="label">{_escape(item.get('label', ''))}</td>
            <td class="detail"><code>{_escape(item.get('detail', ''))}</code></td>
            <td class="match"><code>{_escape(item.get('matched', ''))}</code></td>
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
                    <th>Quando</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
        """
    else:
        msg = finding.get("error") or "Nenhum vestígio encontrado nesta categoria."
        table = f'<p class="empty">{_escape(msg)}</p>'

    return f"""
    <section class="card status-{status}">
        <div class="card-head">
            <h2>{name}</h2>
            <span class="badge" style="background:{badge_color}">{badge_text}</span>
        </div>
        <p class="desc">{desc}</p>
        <p class="summary">{summary}</p>
        {table}
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


def _render_summary(findings: list[dict]) -> str:
    total = sum(len(f["items"]) for f in findings)
    high = sum(1 for f in findings for i in f["items"] if i.get("severity") == "high")
    med  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "medium")
    low  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "low")
    errors = sum(1 for f in findings if f["status"] == "error")

    veredito = "LIMPO"
    veredito_color = "#3fbf7f"
    if high > 0:
        veredito = "CHEATER (HIGH MATCHES)"
        veredito_color = "#ff4d4f"
    elif med > 0:
        veredito = "SUSPEITO (REVISAR)"
        veredito_color = "#ffb020"
    elif low > 0:
        veredito = "POSSÍVEIS PISTAS"
        veredito_color = "#ffe066"

    return f"""
    <section class="card overview">
        <h2>Resumo</h2>
        <div class="big-verdict" style="color:{veredito_color}">{veredito}</div>
        <div class="stats">
            <div class="stat"><div class="num" style="color:#ff4d4f">{high}</div><div>High</div></div>
            <div class="stat"><div class="num" style="color:#ffb020">{med}</div><div>Medium</div></div>
            <div class="stat"><div class="num" style="color:#ffe066">{low}</div><div>Low</div></div>
            <div class="stat"><div class="num">{total}</div><div>Total</div></div>
            <div class="stat"><div class="num" style="color:#888">{errors}</div><div>Skips/Erros</div></div>
        </div>
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
    label_map = {"desktop": "Desktop completo", "roblox": "Janela do Roblox"}
    for key, path in screenshots.items():
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            continue
        pieces.append(f"""
        <div class="shot">
            <div class="shot-label">{_escape(label_map.get(key, key))}</div>
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

    // Click pra copiar em code blocks
    document.querySelectorAll('code').forEach(c => {
        c.style.cursor = 'pointer';
        c.title = 'Clique pra copiar';
        c.addEventListener('click', () => {
            navigator.clipboard.writeText(c.textContent).then(() => {
                const orig = c.style.background;
                c.style.background = '#3fbf7f';
                setTimeout(() => { c.style.background = orig; }, 300);
            }).catch(() => {});
        });
    });
})();
</script>
"""


def generate_html_report(findings: list[dict], sys_info: dict,
                          screenshots: dict = None,
                          high_confidence: dict = None,
                          output_path: str = None) -> str:
    """Gera HTML e retorna o caminho do arquivo salvo."""
    if output_path is None:
        ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            tempfile.gettempdir(),
            f"telador_relatorio_{ts_tag}.html",
        )

    summary_html = _render_summary(findings)
    sys_html = _render_system(sys_info)
    screens_html = _render_screenshots(screenshots or {})
    hc_html = _render_high_confidence(high_confidence or {})
    controls_html = _render_controls()
    sections = "\n".join(_render_section(f) for f in findings)

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
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório do Telador — {sys_info.get('host', '')}</title>
    <style>{CSS}{extra_css}</style>
</head>
<body>
    <header>
        <h1>TELADOR BR</h1>
        <div class="sub">Relatório gerado em {sys_info.get('scan_time', '')}</div>
    </header>
    {summary_html}
    {hc_html}
    {sys_html}
    {screens_html}
    {controls_html}
    {sections}
    <footer>
        Resultado é heurístico (baseado em nomes/locais conhecidos).
        Pode haver falso positivo (ex.: alguém pesquisou sobre o tema) ou falso negativo (cheat com nome trocado).
        Conduza a tela completa e verifique manualmente os pontos suspeitos.
    </footer>
    {CONTROLS_JS}
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    return output_path
