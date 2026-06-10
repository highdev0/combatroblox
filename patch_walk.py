import os

# 1. scanners.py
with open("scanners.py", "r", encoding="utf-8") as f:
    content = f.read()

# For downloads walk
old_dl = '''    try:
        for root, _dirs, files in os.walk(downloads):
            for f in files:'''
new_dl = '''    try:
        dirs_to_visit = [downloads]
        while dirs_to_visit:
            cur = dirs_to_visit.pop()
            try:
                with os.scandir(cur) as it:
                    for entry in it:
                        if entry.is_dir(follow_symlinks=False):
                            dirs_to_visit.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            f = entry.name'''
content = content.replace(old_dl, new_dl)

# Wait, `full = os.path.join(root, f)`
content = content.replace('full = os.path.join(root, f)', 'full = entry.path')

# For walk_capped
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

with open("scanners.py", "w", encoding="utf-8") as f:
    f.write(content)

# 2. removable_media.py
with open("removable_media.py", "r", encoding="utf-8") as f:
    content = f.read()

old_rm = '''def _walk_drive(drive):
    """os.walk isolado num ponto Ãºnico, mockÃ¡vel nos testes. Sem isso, testar o
    scanner exige escrever um arquivo com nome de executor real (ex.: solara.exe)
    no disco â€” que cai no USN journal/Prefetch do host e vira falso positivo no
    prÃ³prio Telador quando ele roda depois."""
    return os.walk(drive)'''

new_rm = '''def _walk_drive(drive):
    """os.walk isolado num ponto Ãºnico, mockÃ¡vel nos testes. Sem isso, testar o
    scanner exige escrever um arquivo com nome de executor real (ex.: solara.exe)
    no disco â€” que cai no USN journal/Prefetch do host e vira falso positivo no
    prÃ³prio Telador quando ele roda depois."""
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

with open("removable_media.py", "w", encoding="utf-8") as f:
    f.write(content)
