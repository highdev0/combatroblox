"""
Matching central de keywords de executor.

Usa WORD-BOUNDARY em vez de substring puro. Diferença prática:

    substring:      "argon" casa "argonauts" (jogo), "trigon" casa "trigonometria"
    word-boundary:  "argon" casa "argon.exe", "/argon/", "argon-x" — mas NÃO
                    casa "argonauts", "darkargon", "scriptwarehouse"...

Reduz falsos positivos de tokens que são substring de palavras maiores,
sem perder detecção de nome real de executor (que sempre vem delimitado
por separador: ponto, barra, espaço, hífen, fim de string).

Mantém a mesma interface/ordem do antigo `_match_keyword`: retorna o
PRIMEIRO match na ordem de inserção de EXECUTOR_KEYWORDS.
"""

import re

from database import EXECUTOR_KEYWORDS

_PATTERNS = None


def _compile():
    """Compila um pattern word-boundary por keyword (uma vez, cacheado)."""
    global _PATTERNS
    pats = []
    for kw, sev in EXECUTOR_KEYWORDS.items():
        if not kw:
            continue
        esc = re.escape(kw)
        # \b só faz sentido quando a borda do keyword é alfanumérica. Se o
        # keyword começa/termina com símbolo (ex.: ".exe" hipotético), a borda
        # vira substring naquele lado — comportamento correto.
        pre = r"\b" if kw[0].isalnum() else ""
        suf = r"\b" if kw[-1].isalnum() else ""
        pats.append((re.compile(pre + esc + suf, re.IGNORECASE), kw, sev))
    _PATTERNS = pats
    return pats


def invalidate():
    """Descarta o cache de patterns. Chamar após mexer em EXECUTOR_KEYWORDS
    (ex.: depois de mesclar signatures.json) pra forçar recompilação."""
    global _PATTERNS
    _PATTERNS = None


def match_keyword(text):
    """Retorna (keyword, severity) do primeiro match, ou (None, None)."""
    if not text:
        return None, None
    pats = _PATTERNS if _PATTERNS is not None else _compile()
    for pat, kw, sev in pats:
        if pat.search(text):
            return kw, sev
    return None, None
