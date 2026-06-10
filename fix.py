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


def word_in_text(word: str, text: str) -> bool:'''
new_code = '''@functools.lru_cache(maxsize=1024)
def _compile_word(word: str) -> re.Pattern:
    esc = re.escape(word.lower())
    pre = r"\\b" if word[0].isalnum() else ""
    suf = r"\\b" if word[-1].isalnum() else ""
    return re.compile(pre + esc + suf)


def word_in_text(word: str, text: str) -> bool:'''
content = content.replace(old_code, new_code)
old_body = '''    pat = _word_cache.get(word)
    if pat is None:
        esc = re.escape(word.lower())
        pre = r"\\b" if word[0].isalnum() else ""
        suf = r"\\b" if word[-1].isalnum() else ""
        pat = re.compile(pre + esc + suf)
        _word_cache[word] = pat'''
new_body = '''    pat = _compile_word(word)'''
content = content.replace(old_body, new_body)
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
# adjust indentations for everything inside the loop until except OSError
start_idx = content.find(new_code) + len(new_code)
end_idx = content.find('            except OSError:', start_idx) # Actually we removed except OSError from that position? Wait, the original code had:
#             except OSError:
#                 continue
# Which I replaced! So I don't have except OSError for the file open anymore.
# Let's fix this.
