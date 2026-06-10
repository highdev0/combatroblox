import os
import re

# 1. fp_filter.py
with open("fp_filter.py", "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace('def is_whitelisted_path(path: str) -> tuple[bool, str | None]:', 'def is_whitelisted_path(path: str) -> tuple[bool, str | None]:\n    import os')
content = re.sub(
    r'    lower = path\.lower\(\)\.replace\("/", "\\\\"\)\n    while "\\\\\\\\" in lower:\n        lower = lower\.replace\("\\\\\\\\", "\\\\"\)\n    for sub in WHITELIST_PATH_SUBSTRINGS:\n        sub_normalized = sub\.replace\("/", "\\\\"\)\.lower\(\)\n        while "\\\\\\\\" in sub_normalized:\n            sub_normalized = sub_normalized\.replace\("\\\\\\\\", "\\\\"\)\n        if sub_normalized in lower:',
    r'    norm_path = os.path.normpath(path).lower()\n    parts = norm_path.split(os.sep)\n    for sub in WHITELIST_PATH_SUBSTRINGS:\n        norm_sub = os.path.normpath(sub).lower().strip(os.sep)\n        if norm_path == norm_sub or norm_path.startswith(norm_sub + os.sep) or norm_sub in parts:',
    content
)
with open("fp_filter.py", "w", encoding="utf-8") as f:
    f.write(content)

# 2. user_accounts.py
with open("user_accounts.py", "r", encoding="utf-8") as f:
    content = f.read()
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
with open("user_accounts.py", "w", encoding="utf-8") as f:
    f.write(content)

# 3. matching.py
with open("matching.py", "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("import re\n", "import re\nimport functools\n")
content = content.replace('''_word_cache = {}


def word_in_text(word: str, text: str) -> bool:''',
'''@functools.lru_cache(maxsize=1024)
def _compile_word(word: str) -> re.Pattern:
    esc = re.escape(word.lower())
    pre = r"\\b" if word[0].isalnum() else ""
    suf = r"\\b" if word[-1].isalnum() else ""
    return re.compile(pre + esc + suf)


def word_in_text(word: str, text: str) -> bool:''')
content = content.replace('''    pat = _word_cache.get(word)
    if pat is None:
        esc = re.escape(word.lower())
        pre = r"\\b" if word[0].isalnum() else ""
        suf = r"\\b" if word[-1].isalnum() else ""
        pat = re.compile(pre + esc + suf)
        _word_cache[word] = pat''',
'''    pat = _compile_word(word)''')
with open("matching.py", "w", encoding="utf-8") as f:
    f.write(content)

# 4. discord_cache.py
with open("discord_cache.py", "r", encoding="utf-8") as f:
    lines = f.read().splitlines()
out_discord = []
in_loop = False
for line in lines:
    if line == '            try:':
        out_discord.append(line)
        in_loop = True
        continue
    if in_loop:
        if line == '                with open(full, "rb") as fh:':
            out_discord.append('                import mmap')
            out_discord.append('                size = os.path.getsize(full)')
            out_discord.append('                if size == 0: continue')
            out_discord.append(line)
            continue
        elif line == '                    blob = fh.read(2_000_000)':
            out_discord.append('                    with mmap.mmap(fh.fileno(), min(size, 2_000_000), access=mmap.ACCESS_READ) as blob:')
            continue
        elif line == '            except OSError:':
            in_loop = False
            out_discord.append(line)
            continue
        
        # indent inner body by 4 spaces
        if line.startswith('            '): # like '            scanned += 1' or '            for match in URL_RE.findall(blob):'
            # actually we only indent if it was at 12 spaces or more. Wait, `            scanned += 1` is 12 spaces.
            # but wait, `blob = fh.read` was 20 spaces. The `with mmap` block starts at 20 spaces, its body must be at 24 spaces!
            if not line.strip():
                out_discord.append(line)
            else:
                # indent all lines except the ones we already handled
                # `scanned += 1` was 12 spaces. It should be 24 spaces! Wait, no, `scanned += 1` was OUTSIDE `with open`. 
                # Let's put `scanned += 1` at 24 spaces inside the `with mmap` block.
                # Actually, any line starting with 12 spaces ('            ') gets +12 spaces to become 24 spaces!
                # Wait, what about '                try:'? It was 16 spaces. It should get +8 spaces to become 24 spaces.
                # Let's just indent by 4 spaces for the `with mmap` block.
                # In original:
                # 16: with open
                # 20: blob = fh.read
                # 12: except OSError:
                # 16: continue
                # 12: scanned += 1
                # 12: for match in ...
                # Let's manually do the replacement string.
                pass

with open("discord_cache.py", "r", encoding="utf-8") as f:
    content = f.read()

old_discord_block = """            try:
                with open(full, "rb") as fh:
                    blob = fh.read(2_000_000)
            except OSError:
                continue
            scanned += 1

            for match in URL_RE.findall(blob):"""

new_discord_block = """            try:
                size = os.path.getsize(full)
                if size == 0: continue
                with open(full, "rb") as fh:
                    import mmap
                    with mmap.mmap(fh.fileno(), min(size, 2_000_000), access=mmap.ACCESS_READ) as blob:
                        scanned += 1
                        for match in URL_RE.findall(blob):"""
content = content.replace(old_discord_block, new_discord_block)
# Now we need to indent everything that was under `for match in URL_RE.findall(blob):`
# In the original file, that loop ended right before `except OSError:` ? No!
# Let's look at original discord_cache.py. `try` was around `with open(...)`
# So `for match` was OUTSIDE the `try`. So `except OSError` was BEFORE the `for` loop!
# Aha!
# Let's fix indentation from `for match` onwards up to `if not found_any_dir:`
# We will just replace it correctly.
parts = content.split('                        for match in URL_RE.findall(blob):')
if len(parts) == 2:
    lines = parts[1].split('
')
    out = []
    for line in lines:
        if line.startswith('                ') and not line.startswith('                    '): out.append('    ' + line)
        elif line.startswith('                    '): out.append('    ' + line)
        else: out.append(line)
    
    # Actually wait, there is a better way. I can just write the whole block out.
    pass

# Let's just write the whole file discord_cache.py manually since I have it.
