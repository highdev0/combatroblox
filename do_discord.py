import ast
with open('discord_cache.py', 'r', encoding='utf-8') as f: content = f.read()
tree = ast.parse(content)
to_remove = []
imports_needed = set()
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in ('_result', '_item', '_fmt_ts'):
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
with open('discord_cache.py', 'w', encoding='utf-8') as f: f.write('\n'.join(new_lines))
