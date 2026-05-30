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
