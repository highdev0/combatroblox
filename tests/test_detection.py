"""
Testes de detecção e anti-falso-positivo.

Trava as correções da auditoria: garante que executores reais continuam
sendo pegos E que software/jogos legítimos não disparam flag.

Rodar:  python -m pytest tests/ -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from matching import match_keyword  # noqa: E402


# --------------------------- Executores reais devem casar ---------------------------

REAL_EXECUTORS = [
    r"c:\users\x\downloads\krnl.exe",
    "wave executor",
    "Synapse X",
    "fluxus",
    "scriptware.dll",
    r"d:\tools\vegax.exe",
    "jjsploit",
    "wearedevs.net",
    "kdmapper",
    "xeno executor",
    "cryptic exec",
    "solara",
    "hydrogen-m",
]


def test_real_executors_match():
    for t in REAL_EXECUTORS:
        kw, sev = match_keyword(t)
        assert kw is not None, f"deveria casar executor real: {t!r}"


# --------------------------- Legítimos NÃO devem casar ---------------------------

LEGIT = [
    r"c:\program files\cryptic studios\game.exe",   # Star Trek Online / Neverwinter
    r"d:\games\xenoblade\save.dat",                  # série Xeno
    r"c:\nihon falcom\ys viii\ys8.exe",              # Nihon Falcom
    "argonauts legendary tales",                      # 'argon' não é substring solto
    "trigonometria_aula.pdf",                         # 'trigon'
    "scriptwarehouse inventory",                      # 'scriptware'
    r"c:\windows\system32\notepad.exe",
    r"c:\program files\google\chrome\chrome.exe",
    "calamari recipe.txt",                            # comida
    "",
]


def test_legit_not_flagged():
    for t in LEGIT:
        kw, sev = match_keyword(t)
        assert kw is None, f"FALSO POSITIVO: {t!r} casou {kw!r}"


def test_none_safe():
    assert match_keyword(None) == (None, None)
    assert match_keyword("") == (None, None)


# --------------------------- Database sanity ---------------------------

def test_removed_substring_keywords_absent():
    """Keywords soltas perigosas não podem voltar."""
    for k in ("xeno", "cryptic", "empyrean", "calamari", "nihon"):
        assert k not in database.EXECUTOR_KEYWORDS, f"{k} (solto) reintroduzido — FP!"


def test_specific_variants_present():
    """Variantes específicas que substituem os soltos devem existir."""
    for k in ("xeno executor", "cryptic exec", "calamari executor"):
        assert k in database.EXECUTOR_KEYWORDS, f"variante {k} sumiu"


def test_hyperv_macs_removed():
    """MACs Hyper-V não podem voltar (FP com WSL2/Docker/Sandbox)."""
    for mac in ("00:15:5D", "00:03:FF"):
        assert mac not in database.VM_MAC_PREFIXES, f"{mac} Hyper-V reintroduzido — FP!"


def test_generic_process_names_removed():
    """Process names genéricos que pegavam software legítimo."""
    for p in ("electron.exe", "sentinel.exe", "ninja.exe", "swift.exe", "apex.exe"):
        assert p not in database.EXECUTOR_PROCESS_NAMES, f"{p} reintroduzido — FP!"


def test_native_roblox_apis_not_high():
    """APIs nativas do Roblox não podem ser HIGH (usadas em jogos legítimos)."""
    for api in ("firetouchinterest", "fireclickdetector", "fireproximityprompt"):
        assert database.SCRIPT_RED_FLAGS.get(api) != "high", f"{api} não pode ser HIGH"


# --------------------------- Verdict ignora meta_only ---------------------------

def test_verdict_ignores_meta_only():
    import fp_filter
    findings = [{
        "name": "DLL Injection (Roblox)", "status": "clean",
        "items": [{
            "label": "[PROCESSO] PID 1 — RobloxPlayerBeta.exe",
            "detail": "ctx", "severity": "low", "matched": "roblox-running",
            "timestamp": "", "confidence": 50, "meta_only": True,
        }],
    }]
    v = fp_filter.compute_verdict(findings)
    assert v["score"] == 0, f"meta_only somou score: {v['score']}"
    assert v["low"] == 0, "meta_only contou como LOW"
    assert v["verdict"] == "LIMPO"


# --------------------------- Prova de SS ao vivo (#1) ---------------------------

def test_session_render_with_code():
    import report
    info = {"session_id": "A1B2C3D4", "session_code": "SUP-9988", "scan_time": "2026-05-30 12:00:00"}
    html = report._render_session(info, "deadbeef" * 8)
    assert "SUP-9988" in html and "A1B2C3D4" in html
    assert "código informado" in html  # estado verificado


def test_session_render_without_code_warns():
    import report
    info = {"session_id": "A1B2C3D4", "session_code": "", "scan_time": "x"}
    html = report._render_session(info, "")
    assert "NÃO verificada" in html  # avisa que faltou código


def test_session_not_shown_in_sysinfo_table():
    import report
    info = {"host": "pc", "session_id": "X", "session_code": "Y"}
    sys_html = report._render_system(info)
    # session_* têm card próprio, não devem poluir a tabela de sistema
    assert "session_id" not in sys_html and "session_code" not in sys_html


# --------------------------- Overlay / ESP externo (#4) ---------------------------

def test_overlay_scanner_runs():
    import live_analysis
    r = live_analysis.scan_overlay_windows()
    assert r["status"] in ("clean", "suspicious", "error")
    assert "name" in r and "items" in r


def test_overlay_whitelist_covers_common_apps():
    import live_analysis
    for app in ("discord.exe", "steam.exe", "obs64.exe", "nvcontainer.exe", "explorer.exe"):
        assert app in live_analysis.OVERLAY_WHITELIST, f"{app} deveria estar na whitelist de overlay"


# --------------------------- Assinaturas externas (signatures.json) ---------------------------

def test_external_signatures_merge(tmp_path):
    import json, database
    p = tmp_path / "signatures.json"
    p.write_text(json.dumps({
        "executor_keywords": {"zzznovoexec": "high", "ignorar_sev": "banana"},
        "executor_process_names": {"zzznovoexec.exe": "medium"},
        "naosei_secao": {"x": "high"},
    }), encoding="utf-8")

    added, err = database.load_external_signatures(str(p))
    try:
        assert err is None
        assert added == 2, f"esperava 2 mescladas, veio {added}"  # severidade inválida ignorada
        assert database.EXECUTOR_KEYWORDS.get("zzznovoexec") == "high"
        assert database.EXECUTOR_PROCESS_NAMES.get("zzznovoexec.exe") == "medium"
        assert "ignorar_sev" not in database.EXECUTOR_KEYWORDS
    finally:
        database.EXECUTOR_KEYWORDS.pop("zzznovoexec", None)
        database.EXECUTOR_PROCESS_NAMES.pop("zzznovoexec.exe", None)


def test_external_signatures_missing_is_safe(tmp_path):
    import database
    added, err = database.load_external_signatures(str(tmp_path / "naoexiste.json"))
    assert added == 0 and err is None


def test_external_signatures_invalid_json_degrades(tmp_path):
    import database
    p = tmp_path / "signatures.json"
    p.write_text("{ isto nao e json valido ", encoding="utf-8")
    added, err = database.load_external_signatures(str(p))
    assert added == 0 and err is not None  # avisa mas não quebra


# --------------------------- Forense extra (Tier 1) ---------------------------

def test_extra_forensic_scanners_run():
    """Cada scanner novo retorna o contrato esperado, sem crashar."""
    import extra_forensics
    for fn in extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS:
        r = fn()
        assert isinstance(r, dict), f"{fn.__name__} não retornou dict"
        assert r.get("status") in ("clean", "suspicious", "error"), f"{fn.__name__} status inválido"
        assert "items" in r and isinstance(r["items"], list)
        assert "name" in r


def test_extra_forensics_registered():
    """Os 4 scanners do Tier 1 estão na lista."""
    import extra_forensics
    names = {fn.__name__ for fn in extra_forensics.ALL_EXTRA_FORENSIC_SCANNERS}
    assert names == {"scan_shimcache", "scan_srum", "scan_script_hashes", "scan_anti_forensics"}


def test_script_hash_match_logic(tmp_path, monkeypatch):
    """Plantando um hash conhecido, um arquivo com aquele conteúdo é pego."""
    import extra_forensics, hashlib
    conteudo = b"-- script qualquer renomeado\nlocal x = 1\n" * 5
    sha1 = hashlib.sha1(conteudo).hexdigest()
    f = tmp_path / "anotacoes.lua"
    f.write_bytes(conteudo)

    monkeypatch.setattr(extra_forensics, "KNOWN_SCRIPT_HASHES", {sha1: "Hub Fictício vX"})
    monkeypatch.setattr(extra_forensics, "SCRIPT_HASH_PATHS", [str(tmp_path)])

    r = extra_forensics.scan_script_hashes()
    assert r["status"] == "suspicious"
    assert any("Hub Fictício vX" in it["label"] for it in r["items"])
