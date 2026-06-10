import os
import re

target_dir = r"c:\Users\gabri\Downloads\combatroblox-3.35.0\combatroblox-3.35.0"

for f in os.listdir(target_dir):
    if not f.endswith('.py') or f == 'models.py':
        continue
        
    path = os.path.join(target_dir, f)
    with open(path, 'r', encoding='utf-8') as fh:
        lines = fh.readlines()
        
    new_lines = []
    skip = False
    modified = False
    has_import = False
    
    for line in lines:
        if 'from models import' in line:
            has_import = True
            
        if re.match(r'^\s*def _result\(', line) or re.match(r'^\s*def _item\(', line) or re.match(r'^\s*def _fmt_ts\(', line):
            skip = True
            modified = True
            continue
            
        if skip:
            if re.match(r'^[a-zA-Z_]', line) and not line.startswith('def _result') and not line.startswith('def _item') and not line.startswith('def _fmt_ts'):
                skip = False
            elif line.startswith('# =================') or line.startswith('# -----') or line.startswith('# =================='):
                skip = False
            else:
                continue
                
        new_lines.append(line)
        
    if modified:
        if not has_import:
            for i, line in enumerate(new_lines):
                if line.startswith('import ') or line.startswith('from '):
                    new_lines.insert(i, "from models import _result, _item, _fmt_ts\n")
                    break
        
        with open(path, 'w', encoding='utf-8') as fh:
            fh.writelines(new_lines)
            
print("Cleaning complete")
