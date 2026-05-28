<div align="center">

<svg width="120" height="120" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff4d4f"/>
      <stop offset="0.5" stop-color="#ff7a3f"/>
      <stop offset="1" stop-color="#ffb020"/>
    </linearGradient>
  </defs>
  <path d="M32 4 L56 14 L56 34 Q56 50 32 60 Q8 50 8 34 L8 14 Z" fill="url(#g)"/>
  <circle cx="26" cy="28" r="9" fill="none" stroke="#0e0e10" stroke-width="3"/>
  <line x1="33" y1="35" x2="42" y2="44" stroke="#0e0e10" stroke-width="3" stroke-linecap="round"/>
  <text x="32" y="56" font-size="6" font-weight="800" fill="#0e0e10" text-anchor="middle" letter-spacing="1.5">TELADOR</text>
</svg>

# Telador BR

**Ferramenta forense local para SS em comunidades Roblox**

[![Latest Release](https://img.shields.io/github/v/release/highdev0/combatroblox?style=for-the-badge&color=ff4d4f)](https://github.com/highdev0/combatroblox/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/highdev0/combatroblox/total?style=for-the-badge&color=ffb020)](https://github.com/highdev0/combatroblox/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/highdev0/combatroblox/ci.yml?style=for-the-badge&label=CI)](https://github.com/highdev0/combatroblox/actions)
[![License](https://img.shields.io/badge/License-MIT-3fbf7f?style=for-the-badge)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/highdev0/combatroblox?style=for-the-badge&color=888)](https://github.com/highdev0/combatroblox/commits/main)

**39 scanners** em paralelo · **542 assinaturas** de detecção · **100% local** · zero envio de dados

</div>

---

## Comece aqui (mais simples)

1. Baixe `telador.exe` da [última release](https://github.com/highdev0/combatroblox/releases/latest)
2. Clique direito → **Executar como administrador** (pra cobertura completa)
3. Pronto. Relatório HTML abre no navegador automático

Pra distribuir pro usuário final: zipe `telador.exe` + `INICIAR.bat`, manda no Discord, instrui dois cliques.

## O que faz

### 🔍 39 scanners em 10 categorias

| Categoria | Cobertura |
|---|---|
| **Execução** | Prefetch, UserAssist, MUICache, Amcache (SHA1), BAM (timestamp exato) |
| **Persistência** | Startup folder, Run/RunOnce, Scheduled Tasks, WER crash dumps |
| **Filesystem** | Recent files, Lixeira ($I parser), JumpLists, Downloads, hidden files |
| **Browser** | Chrome, Edge, Brave, Opera — URLs + downloads |
| **Roblox** | Logs do client, Bloxstrap, bytecode/autoexec dumps, scripts `.lua/.luau` |
| **Live process** | DLL injection scan em `RobloxPlayerBeta.exe` (com `WinVerifyTrust`), process tree |
| **Comportamento** | PowerShell history, RunMRU, TypedPaths, mouse macros (Logitech G HUB Lua, Razer, X-Mouse) |
| **Network** | Conexões TCP/UDP ativas, DNS cache, hosts file (bloqueio de telemetria Roblox), **Discord cache** |
| **Anti-evasão** | VM (VMware/VBox/Hyper-V/QEMU), Sandboxie, clock tampering, **PC formatado pra SS** (6 sinais combinados) |
| **Forensics** | Amcache, BAM, JumpLists, PE analysis com hash matching |

### 🛡️ Filtro de falsos positivos
- **Dev-aware**: detecta Visual Studio/JetBrains/VS Code e rebaixa Cheat Engine/IDA/dnSpy automaticamente
- **Time decay**: hits >30d perdem severity, >90d viram LOW
- **Whitelist contextual**: `.git`, `node_modules`, Steam, system folders ignorados
- **Smart browser**: visita a forum ≠ download direto
- **Veredict ponderado**: score numérico, não só HIGH counter

### 🔬 PE Analysis
SHA256 + parser nativo de PE header em todo `.exe`/`.dll` flagado:
- Compile timestamp (compilado <30d = upgrade)
- Detecta packers (UPX/Themida/VMProtect/Enigma/ASPack/PECompact/MPRESS)
- Hash match contra database de executores conhecidos
- Machine arch (x86/x64/ARM64)

### 📊 Relatório HTML
Dashboard com:
- Sidebar sticky + TOC navegável
- Donut SVG + bar chart (severidade e top scanners)
- Timeline visual de hits (cluster denso = burst suspeito)
- Sections colapsáveis + search/filter live
- Multi-monitor screenshots (TODOS os monitores)
- Lightbox modal pra zoom
- Print-friendly + responsive
- Animations sutis, custom scrollbar

### 🔏 Integridade
- `--save-tsr` salva snapshot HMAC-assinado
- `--diff old.tsr` compara com SS anterior, mostra hits novos/sumidos
- Banner mostra SHA256 do próprio `.exe` pra cara verificar autenticidade

### 🛡️ Privacy
- **Zero network egress** — nada sai do PC
- Redação automática de tokens, passwords, emails, CPF, etc.
- Screenshot pulado se gerenciador de senha estiver aberto
- Open-source, código auditável

## Uso

```bash
# Default — roda tudo
telador.exe

# Modo rápido (15 scanners base, ~1s)
telador.exe --quick

# Sem screenshot
telador.exe --no-screenshot

# Salva snapshot pra comparar depois
telador.exe --save-tsr fulano_2026-05-28.tsr

# Compara com SS anterior
telador.exe --save-tsr fulano_2026-06-28.tsr --diff fulano_2026-05-28.tsr

# Markdown export (colável no Discord)
telador.exe --md

# Modo paranoia (desliga FP-filter)
telador.exe --strict

# Skips opcionais
telador.exe --no-forensics --no-persistence --no-live --no-history --no-peripherals
```

## Build do executável

```bat
build.bat
```

Saída: `dist/telador.exe` (~11MB, sem deps externas no runtime).

## Requirements

- Windows 10/11
- Python 3.10+ (apenas pra build/dev)
- `psutil` (única dep runtime)

```bash
pip install -r requirements.txt
```

## Avisos importantes

- **Detecção é heurística** — pode ter falso negativo (cheat renomeado, versão nova). Conduza SS visual também.
- **Use só em ambiente autorizado**. Não é ferramenta de vigilância — é ferramenta de auditoria com consentimento. Respeite leis locais e políticas da sua comunidade.
- **Antivírus pode flagar `.exe`** — PyInstaller é falso-positivo comum. Compare SHA256 do banner com a release oficial pra verificar autenticidade.

## Segurança

Vulnerabilidades: ver `SECURITY.md`.

## Licença

MIT. Ver `LICENSE`.
