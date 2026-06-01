"""
Fontes forenses adicionais que cheaters raramente sabem que existem
e por isso não limpam. Cada scanner é independente.

  - ShimCache (AppCompatCache): blob binário no registry com últimos
    execs vistos pelo Application Compatibility. Sobrevive a limpa
    de Prefetch/Amcache/UserAssist.
  - SRUM: System Resource Usage Monitor lembra de rede/CPU por
    programa nos últimos ~30 dias. Mesmo apagando o .exe, o nome
    fica.
  - Script content hashing: SHA1 dos .lua/.luau/.txt encontrados,
    comparado com hashes de hubs públicos. Pega script renomeado
    sem keyword.
  - Anti-forense reforçada: detecta uso recente de Bleachbit/
    CCleaner e a combinação "Prefetch+UserAssist+Recent todos
    vazios juntos" (assinatura de cleaner usado pré-SS).
"""

import os
import re
import hashlib
import subprocess
from datetime import datetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============================ helpers ============================

def _result(name, description, items, error=None):
    if error:
        status = "error"
        summary = f"Erro: {error}"
    elif not items:
        status = "clean"
        summary = "Nada encontrado"
    else:
        status = "suspicious"
        summary = f"{len(items)} item(s) suspeito(s)"
    return {
        "name": name, "description": description, "status": status,
        "items": items, "summary": summary, "error": error,
    }


def _item(label, detail, severity, matched, timestamp=""):
    return {
        "label": label, "detail": detail, "severity": severity,
        "matched": matched, "timestamp": timestamp,
    }


def _match(text):
    """Usa o matching central (word-boundary)."""
    import matching
    return matching.match_keyword(text or "")


# ============================ 1. ShimCache (AppCompatCache) ============================

# Caminho do blob no registry. O parser binário muda entre versões do Windows,
# então usamos strategy resiliente: extrai TODAS as strings UTF-16 do blob e
# casa cada uma contra a base. Não é o parser "correto" de campos, mas pega
# os nomes de executáveis sem depender de offsets específicos.
SHIMCACHE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
SHIMCACHE_VALUES = ("AppCompatCache", "AppCompatibility")


def scan_shimcache() -> dict:
    """
    Lê o blob do ShimCache (HKLM\\SYSTEM\\...\\AppCompatCache). Precisa
    de admin. Extrai strings UTF-16 LE e procura por matches.
    Sobrevive a limpa de Prefetch/Amcache.
    """
    if not HAS_WINREG:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="winreg indisponível")

    blob = None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SHIMCACHE_KEY)
    except OSError as e:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error=f"Sem permissão (precisa admin): {e}")

    try:
        for vname in SHIMCACHE_VALUES:
            try:
                data, _ = winreg.QueryValueEx(key, vname)
                if isinstance(data, (bytes, bytearray)) and len(data) > 64:
                    blob = bytes(data)
                    break
            except OSError:
                continue
    finally:
        winreg.CloseKey(key)

    if not blob:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="Valor não encontrado no registry")

    # Decode UTF-16 LE e extrai trechos imprimíveis
    try:
        text = blob.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return _result("ShimCache", "Cache de compatibilidade (execs vistos)",
                       [], error="Decode falhou")

    # Só tokens que terminam em .exe/.dll/.sys — corta o volume de candidatos
    # (e o custo do matching) em 10-100x vs extrair toda string imprimível.
    candidates = re.findall(
        r"[A-Za-z0-9_\-\\/.: ]{4,260}\.(?:exe|dll|sys)", text, re.IGNORECASE)
    items = []
    seen = set()
    for cand in candidates:
        kw, sev = _match(cand)
        if not kw:
            continue
        # Deduplica por (keyword, basename) — uma entrada por exec
        base = cand.strip().rsplit("\\", 1)[-1][:80]
        key_id = (kw, base.lower())
        if key_id in seen:
            continue
        seen.add(key_id)
        items.append(_item(
            label=base or kw,
            detail=cand.strip()[:200],
            severity=sev, matched=kw,
        ))
        if len(items) >= 50:
            break

    return _result("ShimCache",
                   "AppCompatCache — execs vistos pelo Windows (sobrevive a limpa)",
                   items)


# ============================ 2. SRUM (uso de recursos) ============================

# SRUDB.dat é um banco ESE (Extensible Storage Engine). Não temos parser ESE em
# stdlib. Estratégia pragmática: ler bytes do arquivo e extrair strings UTF-16
# que pareçam nomes de exe / paths. Não tem timestamp preciso, mas confirma
# que o exec foi visto pelo SRUM nos últimos ~30 dias.

SRUM_PATH = r"C:\Windows\System32\sru\SRUDB.dat"


def scan_srum() -> dict:
    """
    SRUM lembra de uso de rede/CPU dos últimos ~30 dias por exec. O arquivo
    fica locado pelo serviço DPS — copiar com shutil pode falhar. Estratégia
    simples: tentar abrir read-only e extrair strings; se locado, retorna erro.
    """
    if not os.path.isfile(SRUM_PATH):
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error="SRUDB.dat não encontrado")

    try:
        # Cap em 30MB pra limitar memória/tempo do regex (SRUM típico é 5-30MB).
        # Na prática o arquivo costuma estar locado pelo serviço DPS -> skip.
        with open(SRUM_PATH, "rb") as fh:
            blob = fh.read(30_000_000)
    except (PermissionError, OSError) as e:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error=f"Sem acesso (arquivo locado pelo serviço): {e}")

    # Strings UTF-16 LE dentro do ESE têm length-prefix; ignoramos isso e só
    # decodificamos o blob inteiro. Sobra ruído, mas o matching filtra.
    try:
        text = blob.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error="Decode falhou")

    # Procura por padrões de path (\Windows-style)
    paths = re.findall(r"\\[A-Za-z]:\\[^\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e-\x1f\"<>|]{4,200}", text)
    # Também procura por basenames .exe sem path completo
    bare = re.findall(r"[A-Za-z0-9_\-]{3,40}\.exe", text)

    items = []
    seen = set()
    for cand in list(paths) + list(bare):
        kw, sev = _match(cand)
        if not kw:
            continue
        base = cand.strip().rsplit("\\", 1)[-1][:80].lower()
        if base in seen:
            continue
        seen.add(base)
        items.append(_item(
            label=base,
            detail=cand.strip()[:200],
            severity=sev, matched=kw,
        ))
        if len(items) >= 50:
            break

    return _result("SRUM",
                   "System Resource Usage Monitor — uso por exec nos últimos ~30 dias",
                   items)


# ============================ 3. Hash de scripts conhecidos ============================

# SHA1 do conteúdo de hubs/scripts públicos famosos. Pega script renomeado
# que removeu as keywords óbvias mas manteve o corpo. Vazio por design — a
# comunidade popula via signatures.json ou aditivo direto (KNOWN_SCRIPT_HASHES).
# Formato: "sha1_hex_lowercase": "Nome do script"
KNOWN_SCRIPT_HASHES: dict[str, str] = {
    # exemplos do formato (não são hashes reais — popular conforme samples):
    # "da39a3ee5e6b4b0d3255bfef95601890afd80709": "Owl Hub v1.x",
}

SCRIPT_HASH_EXTS = (".lua", ".luau", ".txt")
SCRIPT_HASH_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%APPDATA%",
    r"%LOCALAPPDATA%",
]


def scan_script_hashes() -> dict:
    """
    Calcula SHA1 do conteúdo de cada .lua/.luau/.txt em pastas comuns e
    confronta com KNOWN_SCRIPT_HASHES. Cap em 5MB por arquivo.

    Útil pra detectar hub público renomeado/comentado (mesmo se mudou
    a string de cabeçalho, o resto do conteúdo bate hash).
    """
    if not KNOWN_SCRIPT_HASHES:
        return _result("Hash de scripts conhecidos",
                       "Confronta SHA1 com base de hubs públicos",
                       [], error="base de hashes vazia (popular KNOWN_SCRIPT_HASHES)")

    items = []
    checked = 0

    for path_tpl in SCRIPT_HASH_PATHS:
        base = os.path.expandvars(path_tpl)
        if not os.path.isdir(base):
            continue
        for root, _dirs, files in os.walk(base):
            # Cap de profundidade pra não estourar
            depth = root[len(base):].count(os.sep)
            if depth > 4:
                continue
            for fname in files:
                if not fname.lower().endswith(SCRIPT_HASH_EXTS):
                    continue
                full = os.path.join(root, fname)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                if size < 100 or size > 5_000_000:
                    continue

                try:
                    with open(full, "rb") as fh:
                        h = hashlib.sha1(fh.read()).hexdigest()
                except (OSError, PermissionError):
                    continue
                checked += 1

                name = KNOWN_SCRIPT_HASHES.get(h)
                if not name:
                    continue
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(full)).strftime("%Y-%m-%d %H:%M:%S")
                except OSError:
                    mtime = ""
                items.append(_item(
                    label=f"{fname}  →  {name}",
                    detail=f"{full}\nSHA1: {h}",
                    severity="high", matched=f"hash:{name}",
                    timestamp=mtime,
                ))
                if len(items) >= 30:
                    return _result("Hash de scripts conhecidos",
                                   f"Confronta SHA1 ({checked} arquivos analisados)",
                                   items)

    return _result("Hash de scripts conhecidos",
                   f"Confronta SHA1 com base de hubs públicos ({checked} arquivos)",
                   items)


# ============================ 4. Anti-forense reforçada ============================
#
# Foca em DOIS sinais que não duplicam o scan_cleaners existente e têm baixo
# falso positivo quando calibrados:
#   (a) Prefetch + Recent + UserAssist TODOS vazios ao mesmo tempo.
#   (b) Log de Security limpo (evento 1102).
#
# Nota de FP: detecção de Bleachbit/CCleaner por mtime de pasta foi REMOVIDA —
# o mtime muda por atualização automática (não só por uso), CCleaner é comum
# demais pra ser sinal forte, e o scan_cleaners já cobre cleaner instalado.


def _count_dir(path, ext=None):
    try:
        files = os.listdir(path)
    except OSError:
        return None
    if ext:
        files = [f for f in files if f.lower().endswith(ext)]
    return len(files)


def _count_userassist():
    """Conta values do UserAssist. None se não deu pra ler."""
    if not HAS_WINREG:
        return None
    total = 0
    try:
        base = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
    except OSError:
        return None
    try:
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(base, i)
            except OSError:
                break
            i += 1
            try:
                count_k = winreg.OpenKey(base, f"{guid}\\Count")
                j = 0
                while True:
                    try:
                        winreg.EnumValue(count_k, j)
                    except OSError:
                        break
                    j += 1
                total += j
                winreg.CloseKey(count_k)
            except OSError:
                continue
    finally:
        winreg.CloseKey(base)
    return total


def scan_anti_forensics() -> dict:
    """
    Sinais de anti-forense, calibrados pra baixo falso positivo:
      - Prefetch + Recent + UserAssist TODOS vazios ao mesmo tempo (medium).
      - Log de Security limpo, evento 1102 (medium).
    """
    items = []

    # --- (a) Fontes históricas vazias simultaneamente ---
    pf_count = _count_dir(r"C:\Windows\Prefetch", ext=".pf")
    rec_count = _count_dir(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"))
    ua_count = _count_userassist()

    empties = []
    available = 0
    for nome, valor, limite in (("Prefetch", pf_count, 30),
                                ("Recent", rec_count, 10),
                                ("UserAssist", ua_count, 20)):
        if valor is None:
            continue
        available += 1
        if valor < limite:
            empties.append(f"{nome}={valor}")

    # Só dispara se as 3 fontes foram lidas E as 3 estão vazias. Exigir as 3
    # juntas evita o FP de SSD com SysMain off (só Prefetch vazia) ou perfil
    # recém-criado (só 1-2 baixos). Severidade MEDIUM, não HIGH: PC novo ou
    # formatação legítima também zeram tudo — quem confirma é o conjunto.
    if available == 3 and len(empties) == 3:
        items.append(_item(
            label="Prefetch, Recent e UserAssist vazios ao mesmo tempo",
            detail="; ".join(empties) +
                   "  ·  pode ser cleaner pré-SS, mas também PC novo / "
                   "recém-formatado / SysMain desativado — verifique contexto",
            severity="medium", matched="anti-forense:multi-empty",
        ))

    # --- (b) Log de Security limpo (evento 1102) ---
    # Limpar o log de Security é incomum em uso normal, mas acontece em
    # manutenção/reinstalação — por isso MEDIUM, não HIGH.
    try:
        r = subprocess.run(
            ["wevtutil", "qe", "Security",
             "/q:*[System[(EventID=1102)]]", "/c:3", "/rd:true", "/f:text"],
            capture_output=True, timeout=10,
        )
        out = ""
        for enc in ("cp850", "cp1252", "utf-8"):
            try:
                out = (r.stdout or b"").decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if "1102" in out and r.returncode == 0:
            m = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", out)
            when = m.group(1) if m else ""
            items.append(_item(
                label="Log de Security foi limpo",
                detail="Evento 1102 detectado"
                       + (f" · {when}" if when else "")
                       + "  ·  incomum em uso normal; também ocorre em reinstalação",
                severity="medium", matched="security-log-cleared",
                timestamp=when,
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return _result("Anti-forense",
                   "Fontes históricas zeradas em conjunto + limpeza do log de Security",
                   items)


ALL_EXTRA_FORENSIC_SCANNERS = [
    scan_shimcache,
    scan_srum,
    scan_script_hashes,
    scan_anti_forensics,
]
