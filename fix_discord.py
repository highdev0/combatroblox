import os
import ast

with open("discord_cache.py", "r", encoding="utf-8") as f:
    content = f.read()

old_dc = '''        for full, mtime in files[:200]:
            try:
                with open(full, "rb") as fh:
                    blob = fh.read(2_000_000)
            except OSError:
                continue
            scanned += 1

            for match in URL_RE.findall(blob):'''
new_dc = '''        for full, mtime in files[:200]:
            try:
                size = os.path.getsize(full)
                if size == 0: continue
                with open(full, "rb") as fh:
                    import mmap
                    with mmap.mmap(fh.fileno(), min(size, 2_000_000), access=mmap.ACCESS_READ) as blob:
                        scanned += 1
                        for match in URL_RE.findall(blob):'''
content = content.replace(old_dc, new_dc)

parts = content.split('                        for match in URL_RE.findall(blob):')
tail = parts[1]
lines = tail.split('\n')
out_lines = []
for line in lines:
    if line == '    return _result(name, description, items, error=error)':
        out_lines.append('            except OSError:')
        out_lines.append('                continue')
        out_lines.append('')
        out_lines.append(line)
        continue
    
    if line.startswith('                ') and not line.startswith('                    '):
        out_lines.append('            ' + line[12:])
    elif line.startswith('                    '):
        out_lines.append('            ' + line[12:])
    elif line == '':
        out_lines.append(line)
    else:
        out_lines.append(line)

content = parts[0] + '                        for match in URL_RE.findall(blob):\n' + '\n'.join(out_lines)

with open("discord_cache.py", "w", encoding="utf-8") as f:
    f.write(content)

with open("discord_cache.py", "r", encoding="utf-8") as f: content = f.read()
tree = ast.parse(content)
to_remove = []
imports_needed = set()
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in ("_result", "_item", "_fmt_ts"):
        to_remove.append((node.lineno, node.end_lineno))
        imports_needed.add(node.name)

lines = content.split('\n')
new_lines = []
for i, line in enumerate(lines):
    skip = False
    for start, end in to_remove:
        if start <= i + 1 <= end:
            skip = True
            break
    if not skip: new_lines.append(line)

import_stmt = f"from models import {', '.join(sorted(list(imports_needed)))}"
insert_idx = 0
in_docstring = False
for i, line in enumerate(new_lines):
    if line.startswith('"""') or line.startswith("'''"):
        in_docstring = not in_docstring
        if not in_docstring:
            insert_idx = i + 1
            continue
    if not in_docstring and (line.startswith('import ') or line.startswith('from ')):
        insert_idx = i + 1
new_lines.insert(insert_idx, import_stmt)

with open("discord_cache.py", "w", encoding="utf-8") as f:
    f.write('\n'.join(new_lines))
