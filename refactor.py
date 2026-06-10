import os
import re

def refactor():
    files = [f for f in os.listdir('.') if f.endswith('.py') and f != 'models.py']
    
    for f in files:
        with open(f, 'r', encoding='utf-8') as file:
            content = file.read()
            
        orig_content = content
        
        # Determine what to import
        has_result = bool(re.search(r'^def _result\(', content, re.MULTILINE))
        has_item = bool(re.search(r'^def _item\(', content, re.MULTILINE))
        has_fmt_ts = bool(re.search(r'^def _fmt_ts\(', content, re.MULTILINE))
        
        imports = []
        if has_result: imports.append('_result')
        if has_item: imports.append('_item')
        if has_fmt_ts: imports.append('_fmt_ts')
        
        if not imports:
            continue
            
        print(f"Refactoring {f}...")
        
        # Remove _result definition
        content = re.sub(r'^def _result\(.*?(?=(?:^def |^# |^[A-Z_]+ =|$))', '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Remove _item definition
        content = re.sub(r'^def _item\(.*?(?=(?:^def |^# |^[A-Z_]+ =|$))', '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Remove _fmt_ts definition
        content = re.sub(r'^def _fmt_ts\(.*?(?=(?:^def |^# |^[A-Z_]+ =|$))', '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Add import at the top after standard imports. Let's just put it near the top.
        import_stmt = f"from models import {', '.join(imports)}\n"
        
        # Find where to insert it: after the last `import ` or `from ` at the top level
        # Or just after the docstring. Let's just put it after `import os` or something.
        lines = content.split('\n')
        insert_idx = 0
        in_docstring = False
        for i, line in enumerate(lines):
            if line.startswith('"""') or line.startswith("'''"):
                in_docstring = not in_docstring
                if not in_docstring:
                    insert_idx = i + 1
                    continue
            
            if not in_docstring and (line.startswith('import ') or line.startswith('from ')):
                insert_idx = i + 1
                
        lines.insert(insert_idx, import_stmt)
        
        with open(f, 'w', encoding='utf-8') as file:
            file.write('\n'.join(lines))

if __name__ == '__main__':
    refactor()
