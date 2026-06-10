import os
import re

# fp_filter.py
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


# user_accounts.py
with open("user_accounts.py", "r", encoding="utf-8") as f:
    content = f.read()

old_code = '    current = os.environ.get("USERNAME", "")'
new_code = '''    import ctypes
    current = ""
    try:
        size = ctypes.c_uint32(256)
        buf = ctypes.create_unicode_buffer(size.value)
        if ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size)):
            current = buf.value
    except Exception:
        current = os.environ.get("USERNAME", "")'''
content = content.replace(old_code, new_code)
with open("user_accounts.py", "w", encoding="utf-8") as f:
    f.write(content)


# matching.py
with open("matching.py", "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("import re\n", "import re\nimport functools\n")
old_code = '''_word_cache = {}


def word_in_text(word: str, text: str) -> bool:
    """Substring com fronteira de palavra \u2014 'wipe' casa 'wipe.exe' mas N\u00c3O
    'swipe'. Pra listas matchadas por substring que t\u00eam termos curtos/comuns
    (ex.: CLEANER_NAMES com 'wipe'/'shred'). Cacheia o pattern por palavra."""
    if not word or not text:
        return False
    pat = _word_cache.get(word)
    if pat is None:
        esc = re.escape(word.lower())
        pre = r"\\b" if word[0].isalnum() else ""
        suf = r"\\b" if word[-1].isalnum() else ""
        pat = re.compile(pre + esc + suf)
        _word_cache[word] = pat
    return bool(pat.search(text.lower()))'''

new_code = '''@functools.lru_cache(maxsize=1024)
def _compile_word(word: str) -> re.Pattern:
    esc = re.escape(word.lower())
    pre = r"\\b" if word[0].isalnum() else ""
    suf = r"\\b" if word[-1].isalnum() else ""
    return re.compile(pre + esc + suf)


def word_in_text(word: str, text: str) -> bool:
    """Substring com fronteira de palavra \u2014 'wipe' casa 'wipe.exe' mas N\u00c3O
    'swipe'. Pra listas matchadas por substring que t\u00eam termos curtos/comuns
    (ex.: CLEANER_NAMES com 'wipe'/'shred'). Cacheia o pattern por palavra."""
    if not word or not text:
        return False
    pat = _compile_word(word)
    return bool(pat.search(text.lower()))'''
content = content.replace(old_code, new_code)
with open("matching.py", "w", encoding="utf-8") as f:
    f.write(content)


# discord_cache.py
with open("discord_cache.py", "r", encoding="utf-8") as f:
    content = f.read()

old_code = '''        for full, mtime in files[:200]:
            try:
                with open(full, "rb") as fh:
                    blob = fh.read(2_000_000)
            except OSError:
                continue
            scanned += 1

            for match in URL_RE.findall(blob):'''

new_code = '''        for full, mtime in files[:200]:
            try:
                size = os.path.getsize(full)
                if size == 0: continue
                with open(full, "rb") as fh:
                    import mmap
                    with mmap.mmap(fh.fileno(), min(size, 2_000_000), access=mmap.ACCESS_READ) as blob:
                        scanned += 1
                        for match in URL_RE.findall(blob):'''

content = content.replace(old_code, new_code)

# fix indentation for the rest of the loop block
# The loop body is currently indented at 16 spaces, it needs to be 28 spaces? No, 4 spaces deeper.
# Let's just indent the rest manually by splitting by `                        for match in URL_RE.findall(blob):`
parts = content.split('                        for match in URL_RE.findall(blob):')
if len(parts) == 2:
    tail = parts[1]
    # find where the loop ends. The loop ends at:
    #             items.append(_item(
    #                 ...
    #             ))
    # Let's just use string replacement on each line. We know the exact lines.
    lines = tail.split('\n')
    new_lines = []
    for line in lines:
        if line.startswith('                ') and not line.startswith('                    '):
            new_lines.append('    ' + line)
        elif line.startswith('                    '):
            new_lines.append('    ' + line)
        elif line.startswith('            '): # The outer loop or try-except blocks
            new_lines.append(line)
        else:
            new_lines.append(line)
    
    # Wait, simple way: we only indent until we hit `            except OSError:` which belongs to the outer block. No, the `except OSError` was replaced!
    # Wait, the `try:` from `for full, mtime in files[:200]: try:` doesn't have an `except OSError:` in the `new_code`, oh wait, I removed `except OSError` from the first part!
    pass

# Better approach for discord_cache.py
import ast
# We can't easily parse and unparse with AST without changing formatting.
