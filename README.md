# Combat Roblox (Telador BR)

Ferramenta de auditoria local para Windows que executa checagens forenses e de processo para identificar indícios de executores e utilitários associados a cheating em Roblox.

## Aviso Importante

Este projeto é para uso defensivo, auditoria e investigação em ambiente autorizado.
Não use para vigilância não autorizada, violação de privacidade, ou qualquer atividade ilegal.
Você é responsável por cumprir as leis locais e políticas da sua organização.

## Recursos

- Varredura local de sinais de execução/processos suspeitos
- Correlação entre múltiplas fontes de evidência
- Relatório HTML e JSON
- Opcional: envio de relatório para webhook do Discord

## Requisitos

- Windows
- Python 3.10+
- Dependências em `requirements.txt`

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

```bash
python telador.py
python telador.py --no-open
python telador.py --json
python telador.py --webhook URL_DO_WEBHOOK
python telador.py --strict-scripts
```

`--strict-scripts` ativa análise agressiva de `.txt` genéricos no scanner de scripts.
Útil para investigação profunda, mas pode aumentar falso positivo.

## Build do executável

No Windows:

```bat
build.bat
```

Saída esperada: `dist/telador.exe`.

## Privacidade e Dados

- A coleta acontece localmente.
- Dados só saem da máquina se webhook for configurado.
- Revise o código antes do uso em produção.

## Segurança

Se encontrar uma vulnerabilidade, consulte `SECURITY.md`.

## Licença

Distribuído sob licença MIT. Veja `LICENSE`.
