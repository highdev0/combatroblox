import os

with open('discord_cache.py', 'r', encoding='utf-8') as f:
    lines = f.read().splitlines()

out = []
for line in lines:
    if line.startswith('                if url in seen_urls:'): out.append('                            if url in seen_urls:')
    elif line.startswith('                    continue'): out.append('                                continue')
    elif line.startswith('                seen_urls.add(url)'): out.append('                            seen_urls.add(url)')
    elif line.startswith('                import matching'): out.append('                            import matching')
    elif line.startswith('                matched_kw = None'): out.append('                            matched_kw = None')
    elif line.startswith('                severity = None'): out.append('                            severity = None')
    elif line.startswith('                ulow = url.lower()'): out.append('                            ulow = url.lower()')
    elif line.startswith('                for dom, sev in SUSPICIOUS_DOMAINS.items():'): out.append('                            for dom, sev in SUSPICIOUS_DOMAINS.items():')
    elif line.startswith('                    if matching.domain_in_text(dom, ulow):'): out.append('                                if matching.domain_in_text(dom, ulow):')
    elif line.startswith('                        matched_kw, severity = dom, sev'): out.append('                                    matched_kw, severity = dom, sev')
    elif line.startswith('                        break'): out.append('                                    break')
    elif line.startswith('                if not matched_kw:'): out.append('                            if not matched_kw:')
    elif line.startswith('                    kw, sev = matching.match_keyword(url)'): out.append('                                kw, sev = matching.match_keyword(url)')
    elif line.startswith('                    if kw:'): out.append('                                if kw:')
    elif line.startswith('                        matched_kw, severity = kw, sev'): out.append('                                    matched_kw, severity = kw, sev')
    elif line.startswith('                is_download = any(url.endswith(ext) for ext in'): out.append('                            is_download = any(url.endswith(ext) for ext in')
    elif line.startswith('                                  (".exe", ".dll", ".zip", ".rar", ".7z", ".msi"))'): out.append('                                              (".exe", ".dll", ".zip", ".rar", ".7z", ".msi"))')
    elif line.startswith('                if not is_download and severity == "high":'): out.append('                            if not is_download and severity == "high":')
    elif line.startswith('                    severity = "medium"'): out.append('                                severity = "medium"')
    elif line.startswith('                ts = datetime.fromtimestamp(mtime).strftime'): out.append('                            ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")')
    elif line.startswith('                display = url if len(url) < 80'): out.append('                            display = url if len(url) < 80 else url[:77] + "..."')
    elif line.startswith('                detail_note = "" if is_download'): out.append('                            detail_note = "" if is_download else "
⚠ Apenas visita em cache — não confirma download."')
    elif line.startswith('                items.append(_item('): out.append('                            items.append(_item(')
    elif line.startswith('                    label=f"Link suspeito: {url}",'): out.append('                                label=f"Link suspeito: {url}",')
    elif line.startswith('                    detail=f"Arquivo cache: {full}
URL cacheada pelo Discord.
Contexto: o client baixou/acessou esse conteúdo, não necessariamente clicado pelo usuário, mas é um indício.{detail_note}",'): out.append('                                detail=f"Arquivo cache: {full}
URL cacheada pelo Discord.
Contexto: o client baixou/acessou esse conteúdo, não necessariamente clicado pelo usuário, mas é um indício.{detail_note}",')
    elif line.startswith('                    severity=severity,'): out.append('                                severity=severity,')
    elif line.startswith('                    matched=matched_kw,'): out.append('                                matched=matched_kw,')
    elif line.startswith('                    timestamp=ts,'): out.append('                                timestamp=ts,')
    elif line.startswith('                ))'): out.append('                            ))')
    elif line.startswith('                # Match contra database'): out.append('                            # Match contra database')
    elif line.startswith('                # dom\u00ednio + word-boundary'): out.append('                            # dom\u00ednio + word-boundary')
    elif line.startswith('                # Rebaixa severity:'): out.append('                            # Rebaixa severity:')
    elif line.startswith('                # servidor de cheats'): out.append('                            # servidor de cheats')
    elif line.startswith('                # S\u00f3 mant\u00e9m HIGH'): out.append('                            # S\u00f3 mant\u00e9m HIGH')
    elif line.startswith('                # (download direto,'): out.append('                            # (download direto,')
    elif line.startswith('                # Trunca URL'): out.append('                            # Trunca URL')
    elif line == '': out.append('')
    else: out.append(line)

out.append('            except OSError:')
out.append('                continue')

with open('discord_cache.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))
