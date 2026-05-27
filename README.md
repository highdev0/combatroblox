# Combat Roblox (Telador BR)

Ferramenta de auditoria local para Windows que executa checagens forenses e de processo para identificar indícios de executores e utilitários associados a cheating em Roblox.

## Comece Aqui (Simples)

Se você vai compartilhar com outras pessoas, manda este guia:

- [TUTORIAL.md](TUTORIAL.md)
- [INICIAR.bat](INICIAR.bat)

Fluxo mais fácil para usuário final: baixar, extrair e dar 2 cliques em `INICIAR.bat`.
Ele abre o `.exe` se existir; se não existir, roda via Python automaticamente.

## Aviso Importante

Este projeto é para uso defensivo, auditoria e investigação em ambiente autorizado.
Não use para vigilância não autorizada, violação de privacidade, ou qualquer atividade ilegal.
Você é responsável por cumprir as leis locais e políticas da sua organização.

## Recursos

- Varredura local de sinais de execução/processos suspeitos
- Correlação entre múltiplas fontes de evidência
- Relatório HTML e JSON
- Redação automática de credenciais/tokens/emails no relatório
- Screenshot privacy-aware (pula captura se houver password manager aberto)

## Requisitos

- Windows
- Python 3.10+
- Dependências em `requirements.txt`

## Instalação

```bash
pip install -r requirements.txt
```

## Tutorial Rápido (1 minuto)

```powershell
cd "C:\Users\SEU_USUARIO\Desktop\combat-roblox"
./INICIAR.bat
```

## Uso

```bash
python telador.py
python telador.py --no-open
python telador.py --json
python telador.py --strict-scripts
python telador.py --no-redact
python telador.py --force-screenshot
```

No modo padrão, o scanner de scripts analisa `.lua` e `.luau`.

`--strict-scripts` ativa análise agressiva incluindo `.txt` genéricos.
Útil para investigação profunda, mas pode aumentar falso positivo.

## Build do executável

No Windows:

```bat
build.bat
```

Saída esperada: `dist/telador.exe`.

## Privacidade e Dados

- A coleta acontece localmente.
- Por padrão, dados sensíveis em findings são mascarados (`[REDACTED]`).
- Se houver gerenciador de senha aberto, screenshot é pulado por padrão.
- Revise o código antes do uso em produção.

## Segurança

Se encontrar uma vulnerabilidade, consulte `SECURITY.md`.

## Licença

Distribuído sob licença MIT. Veja `LICENSE`.
