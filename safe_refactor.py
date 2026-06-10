import os
import ast
import re

# 1. create models.py
models_code = """import datetime

with open("models.py", "w", encoding="utf-8") as f:
    f.write(models_code)

# 2. fp_filter.py
with open("fp_filter.py", "r", encoding="utf-8") as f: content = f.read()
content = content.replace('def is_whitelisted_path(path: str) -> tuple[bool, str | None]:', 'def is_whitelisted_path(path: str) -> tuple[bool, str | None]:\\n    import os')
content = re.sub(
    r'    lower = path\.lower\(\)\.replace\("/", "\\\\\\\\"\)\\n    while "\\\\\\\\\\\\\\\\" in lower:\\n        lower = lower\.replace\("\\\\\\\\\\\\\\\\", "\\\\\\\\"\)\\n    for sub in WHITELIST_PATH_SUBSTRINGS:\\n        sub_normalized = sub\.replace\("/", "\\\\\\\\"\)\.lower\(\)\\n        while "\\\\\\\\\\\\\\\\" in sub_normalized:\\n            sub_normalized = sub_normalized\.replace\("\\\\\\\\\\\\\\\\", "\\\\\\\\"\)\\n        if sub_normalized in lower:',
    r'    norm_path = os.path.normpath(path).lower()\\n    parts = norm_path.split(os.sep)\\n    for sub in WHITELIST_PATH_SUBSTRINGS:\\n        norm_sub = os.path.normpath(sub).lower().strip(os.sep)\\n        if norm_path == norm_sub or norm_path.startswith(norm_sub + os.sep) or norm_sub in parts:',
    content
)
with open("fp_filter.py", "w", encoding="utf-8") as f: f.write(content)

# 3. user_accounts.py
with open("user_accounts.py", "r", encoding="utf-8") as f: content = f.read()
content = content.replace('    current = os.environ.get("USERNAME", "")',
'''    import ctypes
    current = ""
    try:
        size = ctypes.c_uint32(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
            current = buf.value
    except Exception:
        current = os.environ.get("USERNAME", "")''')
with open("user_accounts.py", "w", encoding="utf-8") as f: f.write(content)

# 4. matching.py
with open("matching.py", "r", encoding="utf-8") as f: content = f.read()
content = content.replace("import re\\n", "import re\\nimport functools\\n")
content = content.replace('''_word_cache = {}


def word_in_text(word: str, text: str) -> bool:''',
'''@functools.lru_cache(maxsize=1024)
def _compile_word(word: str) -> re.Pattern:
    esc = re.escape(word.lower())
    pre = r"\\\\b" if word[0].isalnum() else ""
    suf = r"\\\\b" if word[-1].isalnum() else ""
    return re.compile(pre + esc + suf)


def word_in_text(word: str, text: str) -> bool:''')
content = content.replace('''    pat = _word_cache.get(word)
    if pat is None:
        esc = re.escape(word.lower())
        pre = r"\\\\b" if word[0].isalnum() else ""
        suf = r"\\\\b" if word[-1].isalnum() else ""
        pat = re.compile(pre + esc + suf)
        _word_cache[word] = pat''',
'''    pat = _compile_word(word)''')
with open("matching.py", "w", encoding="utf-8") as f: f.write(content)

# 5. extra_forensics.py
with open("extra_forensics.py", "r", encoding="utf-8") as f: content = f.read()
old_srum = '''    try:
        # Cap em 30MB pra limitar memória/tempo do regex (SRUM típico é 5-30MB).
        # Na prática o arquivo costuma estar locado pelo serviço DPS -> skip.
        with open(SRUM_PATH, "rb") as fh:
            blob = fh.read(30_000_000)
    except (PermissionError, OSError) as e:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error=f"Sem acesso (arquivo locado pelo serviço): {e}")

    # Strings UTF-16 LE dentro do ESE têm length-prefix; ignoramos isso e só
    # decodificamos o blob inteiro. Sobra ruído, mas o matching filtra.
    try:
        text = blob.decode("utf-16-le", errors="replace")
    except UnicodeDecodeError:
        return _result("SRUM", "System Resource Usage Monitor", [],
                       error="Decode falhou")'''
new_srum = '''    try:
        import mmap
        size = os.path.getsize(SRUM_PATH)
        if size == 0: return _result("SRUM", "System Resource Usage Monitor", [], error="Arquivo vazio")
        with open(SRUM_PATH, "rb") as fh:
            with mmap.mmap(fh.fileno(), min(size, 30_000_000), access=mmap.ACCESS_READ) as blob:
                try:
                    text = bytes(blob).decode("utf-16-le", errors="replace")
                except UnicodeDecodeError:
                    return _result("SRUM", "System Resource Usage Monitor", [], error="Decode falhou")
    except (PermissionError, OSError) as e:
        return _result("SRUM", "System Resource Usage Monitor", [], error=f"Sem acesso (arquivo locado pelo serviço): {e}")'''
content = content.replace(old_srum, new_srum)
old_sha = '''                try:
                    with open(full, "rb") as fh:
                        h = hashlib.sha1(fh.read()).hexdigest()
                except (OSError, PermissionError):
                    continue'''
new_sha = '''                try:
                    import mmap
                    size = os.path.getsize(full)
                    if size == 0: continue
                    with open(full, "rb") as fh:
                        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                            h = hashlib.sha1(blob).hexdigest()
                except (OSError, PermissionError):
                    continue'''
content = content.replace(old_sha, new_sha)
with open("extra_forensics.py", "w", encoding="utf-8") as f: f.write(content)

# 6. discord_cache.py
with open("discord_cache.py", "r", encoding="utf-8") as f: content = f.read()
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
lines = tail.split('\\n')
out_lines = []
in_for = True
for line in lines:
    if line == '    return _result(name, description, items, error=error)':
        in_for = False
        out_lines.append('            except OSError:')
        out_lines.append('                continue')
        out_lines.append('')
        out_lines.append(line)
        continue

    if in_for:
        if line == '':
            out_lines.append(line)
        else:
            out_lines.append('            ' + line)
    else:
        out_lines.append(line)
content = parts[0] + '                        for match in URL_RE.findall(blob):\\n' + '\\n'.join(out_lines)
with open("discord_cache.py", "w", encoding="utf-8") as f: f.write(content)

# 7. scanners.py
with open("scanners.py", "r", encoding="utf-8") as f: content = f.read()
old_dl = '''    try:
        for root, _dirs, files in os.walk(downloads):
            for f in files:
                keyword, severity = _match_keyword(f)
                if not keyword:
                    continue
                full = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(full)
                    ts = _fmt_ts(mtime)
                except OSError:
                    ts = ""

                items.append(_item(
                    label=f,
                    detail=full,
                    severity=severity,
                    matched=keyword,
                    timestamp=ts,
                ))'''
new_dl = '''    try:
        dirs_to_visit = [downloads]
        while dirs_to_visit:
            cur = dirs_to_visit.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False): dirs_to_visit.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            f = entry.name
                            keyword, severity = _match_keyword(f)
                            if not keyword: continue
                            full = entry.path
                            try:
                                mtime = entry.stat().st_mtime
                                ts = _fmt_ts(mtime)
                            except OSError: ts = ""
                            items.append(_item(label=f, detail=full, severity=severity, matched=keyword, timestamp=ts))
            except OSError: pass'''
content = content.replace(old_dl, new_dl)

old_wc = '''    def walk_capped(root_path: str, max_depth: int):
        root_depth = root_path.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root_path):
            depth = dirpath.count(os.sep) - root_depth
            if depth >= max_depth:
                dirnames[:] = []
                continue
            yield dirpath, filenames'''
new_wc = '''    def walk_capped(root_path: str, max_depth: int):
        dirs = [(root_path, 0)]
        while dirs:
            cur, depth = dirs.pop()
            if depth >= max_depth: continue
            try:
                with os.scandir(cur) as it:
                    fnames = []
                    subdirs = []
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False): subdirs.append((entry.path, depth + 1))
                        elif entry.is_file(follow_symlinks=False): fnames.append(entry.name)
                yield cur, fnames
                dirs.extend(reversed(subdirs))
            except OSError: continue'''
content = content.replace(old_wc, new_wc)
with open("scanners.py", "w", encoding="utf-8") as f: f.write(content)

# 8. removable_media.py
with open("removable_media.py", "r", encoding="utf-8") as f: content = f.read()
old_rm = '''def _walk_drive(drive):
    """os.walk isolado num ponto único, mockável nos testes. Sem isso, testar o
    scanner exige escrever um arquivo com nome de executor real (ex.: solara.exe)
    no disco — que cai no USN journal/Prefetch do host e vira falso positivo no
    próprio Telador quando ele roda depois."""
    return os.walk(drive)'''
new_rm = '''def _walk_drive(drive):
    """os.walk isolado num ponto único, mockável nos testes. Sem isso, testar o
    scanner exige escrever um arquivo com nome de executor real (ex.: solara.exe)
    no disco — que cai no USN journal/Prefetch do host e vira falso positivo no
    próprio Telador quando ele roda depois."""
    dirs = [drive]
    while dirs:
        cur = dirs.pop()
        try:
            with os.scandir(cur) as it:
                dnames, fnames = [], []
                for entry in it:
                    if entry.is_dir(follow_symlinks=False): dnames.append(entry.name)
                    elif entry.is_file(follow_symlinks=False): fnames.append(entry.name)
            yield cur, dnames, fnames
            for d in reversed(dnames): dirs.append(os.path.join(cur, d))
        except OSError: pass'''
content = content.replace(old_rm, new_rm)
with open("removable_media.py", "w", encoding="utf-8") as f: f.write(content)


# ---------------- PHASE 2 (MODELS) ----------------
files = [f for f in os.listdir('.') if f.endswith('.py') and f not in ('models.py', 'safe_refactor.py')]
for fname in files:
    with open(fname, "r", encoding="utf-8") as f:
        content = f.read()
    
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        print(f"SyntaxError in {fname}: {e}")
        continue
        
    to_remove = []
    imports_needed = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in ("_result", "_item", "_fmt_ts"):
            to_remove.append((node.lineno, node.end_lineno))
            imports_needed.add(node.name)
            
    if not imports_needed:
        continue
        
    lines = content.split('\\n')
    new_lines = []
    for i, line in enumerate(lines):
        line_num = i + 1
        skip = False
        for start, end in to_remove:
            if start <= line_num <= end:
                skip = True
                break
        if not skip:
            new_lines.append(line)
            
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
    
    with open(fname, "w", encoding="utf-8") as f:
        f.write('\\n'.join(new_lines))
    print(f"Refactored {fname} with {imports_needed}")
