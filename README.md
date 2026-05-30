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

40 scanners em paralelo · 542 assinaturas de detecção · execução local, sem envio de dados

</div>

---

## Comece aqui (mais simples)

1. Baixe `telador.exe` da [última release](https://github.com/highdev0/combatroblox/releases/latest)
2. Clique direito → **Executar como administrador** (pra cobertura completa)
3. Pronto. Relatório HTML abre no navegador automático

Pra distribuir pro usuário final: zipe `telador.exe` + `INICIAR.bat`, manda no Discord, instrui dois cliques.

## O que faz

### Scanners (40, em 10 categorias)

| Categoria | Cobertura |
|---|---|
| Execução | Prefetch, UserAssist, MUICache, Amcache (SHA1), BAM (timestamp exato) |
| Persistência | Pasta Startup, Run/RunOnce, Scheduled Tasks, dumps do WER |
| Sistema de arquivos | Arquivos recentes, Lixeira (parser $I), JumpLists, Downloads, arquivos ocultos |
| Navegador | Chrome, Edge, Brave, Opera (URLs e downloads) |
| Roblox | Logs do client, Bloxstrap, dumps de script/autoexec, scripts `.lua`/`.luau` |
| Processo ao vivo | DLLs carregadas no `RobloxPlayerBeta.exe` (WinVerifyTrust), árvore de processo, overlay/ESP externo |
| Comportamento | Histórico do PowerShell, Win+R, barra do Explorer, macros de mouse (G HUB, Razer, X-Mouse) |
| Rede | Conexões TCP/UDP, cache de DNS, arquivo hosts, cache do Discord |
| Anti-evasão | VM (VMware/VBox/Hyper-V/QEMU), Sandboxie, relógio alterado, formatação recente |
| Forense | Amcache, BAM, JumpLists, análise PE com comparação de hash |

### Filtro de falsos positivos
- Detecta ambiente de desenvolvimento (Visual Studio, JetBrains, VS Code) e rebaixa ferramentas como Cheat Engine e IDA.
- Decaimento por tempo: itens com mais de 30 dias perdem severidade; acima de 90 dias viram baixa.
- Caminhos ignorados: `.git`, `node_modules`, biblioteca Steam, pastas de sistema.
- Contexto de navegador: visita a fórum não equivale a download.
- Veredito ponderado por severidade e confiança, não apenas contagem.

### Análise PE
SHA256 e leitura nativa do cabeçalho PE de cada executável encontrado:
- Data de compilação (recente eleva a severidade).
- Detecção de empacotadores (UPX, Themida, VMProtect, Enigma, ASPack, PECompact, MPRESS).
- Comparação de hash com uma base de executores conhecidos.
- Arquitetura (x86/x64/ARM64).

### Relatório HTML
- Barra lateral fixa com índice e contador por scanner.
- Gráficos em SVG (severidade e scanners com mais itens).
- Linha do tempo dos itens.
- Seções recolhíveis e busca/filtro em tempo real.
- Capturas de todos os monitores, com visualização ampliada.
- Estilos de impressão e layout responsivo.

### Verificação de sessão e integridade
- `--codigo`: código informado pelo supervisor entra no relatório assinado, evitando reaproveitar relatórios antigos.
- `--save-tsr` salva um instantâneo assinado por HMAC; `--diff` compara com um anterior.
- O programa exibe o próprio SHA256 no banner para conferência.

### Privacidade
- Execução totalmente local, sem envio de dados pela rede.
- Mascara automaticamente tokens, senhas, e-mails e CPF no relatório.
- Não captura a tela se houver gerenciador de senhas aberto.
- Código aberto e auditável.

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
