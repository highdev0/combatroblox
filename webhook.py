"""
Envia o relatório pro Discord via webhook.
Sem dependências externas — só urllib + json.
"""

import os
import json
import mimetypes
import urllib.request
from datetime import datetime


def _build_embed(findings: list[dict], sys_info: dict) -> dict:
    """Monta o embed do Discord baseado nos findings."""
    total = sum(len(f["items"]) for f in findings)
    high  = sum(1 for f in findings for i in f["items"] if i.get("severity") == "high")
    med   = sum(1 for f in findings for i in f["items"] if i.get("severity") == "medium")
    low   = sum(1 for f in findings for i in f["items"] if i.get("severity") == "low")
    err   = sum(1 for f in findings if f["status"] == "error")

    if high > 0:
        color = 0xFF4D4F      # vermelho
        title = "🚨 CHEATER (HIGH MATCHES)"
    elif med > 0:
        color = 0xFFB020      # laranja
        title = "⚠ SUSPEITO (REVISAR)"
    elif low > 0:
        color = 0xFFE066      # amarelo
        title = "🔍 POSSÍVEIS PISTAS"
    else:
        color = 0x3FBF7F      # verde
        title = "✅ LIMPO"

    # Campos: cada categoria com hit
    fields = []
    for f in findings:
        if not f["items"]:
            continue
        worst = "high" if any(i.get("severity") == "high" for i in f["items"]) else \
                "medium" if any(i.get("severity") == "medium" for i in f["items"]) else "low"
        emoji = {"high": "🔴", "medium": "🟠", "low": "🟡"}[worst]
        top_items = []
        for it in f["items"][:3]:
            line = f"• `{it.get('label', '')}` — {it.get('matched', '')}"
            if it.get("timestamp"):
                line += f" ({it['timestamp']})"
            top_items.append(line)
        rest = ""
        if len(f["items"]) > 3:
            rest = f"\n... +{len(f['items']) - 3} mais"
        value = ("\n".join(top_items) + rest)[:1024]
        fields.append({
            "name":  f"{emoji} {f['name']} ({len(f['items'])})",
            "value": value,
            "inline": False,
        })

    description = (
        f"**Host:** `{sys_info.get('host', '?')}`  "
        f"**Usuário:** `{sys_info.get('user', '?')}`\n"
        f"**OS:** {sys_info.get('os', '?')}\n"
        f"**Scan:** {sys_info.get('scan_time', '?')}\n\n"
        f"🔴 **{high}** high   🟠 **{med}** medium   🟡 **{low}** low   "
        f"⚪ **{err}** skip/erro"
    )

    return {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields[:25],  # Discord limita 25 campos
        "footer": {"text": "Telador BR — relatório automático"},
        "timestamp": datetime.now().isoformat(),
    }


def send(webhook_url: str,
         findings: list[dict],
         sys_info: dict,
         attachments: list[str] = None) -> tuple[bool, str]:
    """
    Envia o relatório pro webhook. Retorna (sucesso, mensagem).

    `attachments` é lista de paths (HTML, screenshots). Discord aceita até 10MB total.
    """
    embed = _build_embed(findings, sys_info)
    payload = {
        "username": "Telador BR",
        "embeds": [embed],
    }

    attachments = attachments or []
    # Filtra anexos que existem e estão dentro de um limite razoável
    safe_attachments = []
    total_size = 0
    for path in attachments:
        if not path or not os.path.isfile(path):
            continue
        try:
            sz = os.path.getsize(path)
        except OSError:
            continue
        if total_size + sz > 8 * 1024 * 1024:  # 8MB limite seguro
            continue
        total_size += sz
        safe_attachments.append(path)

    try:
        if not safe_attachments:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                if 200 <= resp.status < 300:
                    return True, f"Enviado ({resp.status})"
                return False, f"HTTP {resp.status}"
        else:
            body, content_type = _build_multipart(payload, safe_attachments)
            req = urllib.request.Request(
                webhook_url, data=body, method="POST",
                headers={"Content-Type": content_type},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    return True, f"Enviado com {len(safe_attachments)} anexo(s) ({resp.status})"
                return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"Erro de rede: {e.reason}"
    except Exception as e:
        return False, f"Erro: {e}"


def _build_multipart(payload: dict, attachments: list[str]) -> tuple[bytes, str]:
    """Monta multipart/form-data manualmente."""
    boundary = "----TeladorBR" + datetime.now().strftime("%Y%m%d%H%M%S%f")
    parts = []

    # payload_json
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(b'Content-Disposition: form-data; name="payload_json"\r\n')
    parts.append(b"Content-Type: application/json\r\n\r\n")
    parts.append(json.dumps(payload).encode("utf-8"))
    parts.append(b"\r\n")

    # Anexos
    for i, path in enumerate(attachments):
        fname = os.path.basename(path)
        ctype, _ = mimetypes.guess_type(fname)
        ctype = ctype or "application/octet-stream"

        try:
            with open(path, "rb") as fh:
                content = fh.read()
        except OSError:
            continue

        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="files[{i}]"; filename="{fname}"\r\n'.encode()
        )
        parts.append(f"Content-Type: {ctype}\r\n\r\n".encode())
        parts.append(content)
        parts.append(b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"
