import os

with open('discord_cache.py', 'r', encoding='utf-8') as f:
    lines = f.read().splitlines()

out = []
in_loop = False
for line in lines:
    if line.strip() == 'for match in URL_RE.findall(blob):':
        in_loop = True
        out.append(line)
        continue
    
    if in_loop:
        if line.strip() == 'except OSError:':
            in_loop = False
            out.append('            except OSError:')
            continue
            
        if line.startswith('                '):
            out.append('            ' + line[12:])
        elif line.startswith('                    '):
            out.append('            ' + line[12:])
        elif line == '':
            out.append(line)
        else:
            out.append(line)
    else:
        out.append(line)

with open('discord_cache.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))
