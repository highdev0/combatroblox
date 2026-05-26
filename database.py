"""
Banco de assinaturas conhecidas — executores Roblox, ferramentas auxiliares,
sinais de VM/Sandbox e padrões em scripts Lua.

Severity:
  high   = match direto (quase certeza)
  medium = ferramenta auxiliar ou bypass
  low    = palavra-chave ambígua
"""

EXECUTOR_KEYWORDS = {
    # PC Executors
    "synapse":          "high",
    "synapsex":         "high",
    "synapse x":        "high",
    "krnl":             "high",
    "krnl.exe":         "high",
    "krnl.dll":         "high",
    "fluxus":           "high",
    "wave executor":    "high",
    "wave.exe":         "high",
    "wave.cx":          "high",
    "solara":           "high",
    "velocity executor":"high",
    "electron exploit": "high",
    "sentinel exploit": "high",
    "trigon evo":       "high",
    "argon executor":   "high",
    "awp.gg":           "high",
    "zorara":           "high",
    "volcano executor": "high",
    "vegax":            "high",
    "swift executor":   "high",
    "nezur":            "high",
    "nihon":            "high",
    "calamari executor":"high",
    "pandadev":         "high",
    "frontier executor":"high",
    "oxygen u":         "high",
    "comet executor":   "high",
    "jjsploit":         "high",
    "jjsploitv":        "high",
    "wearedevs":        "high",
    "wrd-api":          "high",
    "hydrogen-m":       "high",
    "hydrogen.exe":     "high",
    "codex executor":   "high",
    "codex.lol":        "high",
    "arceus x":         "high",
    "arceusx":          "high",
    "delta executor":   "high",
    "delta exploit":    "high",
    "ronin executor":   "high",
    "potassium executor":"high",
    "evon executor":    "high",
    "scriptware":       "high",
    "protosmasher":     "high",
    "sirhurt":          "high",
    "calamari":         "high",
    "byfron bypass":    "high",
    "hyperion bypass":  "high",
    "bypass roblox":    "high",
    "v3rmillion":       "medium",
    "rscripts":         "low",
    "scriptblox":       "low",
    "cheat engine":     "medium",
    "cheatengine":      "medium",
    "process hacker":   "medium",
    "system informer":  "medium",
    "extreme injector": "medium",
    "xenos injector":   "medium",
    "manualmap":        "medium",
    "dll injector":     "medium",
    "roblox account manager": "low",
    "ram-master":       "low",
}

EXECUTOR_PROCESS_NAMES = {
    "krnl.exe":             "high",
    "fluxus.exe":           "high",
    "wave.exe":             "high",
    "solara.exe":           "high",
    "velocity.exe":         "high",
    "electron.exe":         "high",
    "sentinel.exe":         "high",
    "trigon.exe":           "high",
    "argon.exe":            "high",
    "zorara.exe":           "high",
    "vegax.exe":            "high",
    "swift.exe":            "high",
    "nezur.exe":            "high",
    "nihon.exe":            "high",
    "hydrogen.exe":         "high",
    "codex.exe":            "high",
    "jjsploit.exe":         "high",
    "synapse.exe":          "high",
    "synapsex.exe":         "high",
    "synapselauncher.exe":  "high",
    "wave-bootstrapper.exe":"high",
    "solara-bootstrapper.exe":"high",
    "krnl-bootstrapper.exe":"high",
    "fluxus-bootstrapper.exe":"high",
    "cheatengine-x86_64.exe": "medium",
    "cheatengine-i386.exe":   "medium",
    "processhacker.exe":      "medium",
    "systeminformer.exe":     "medium",
    "extremeinjector.exe":    "medium",
    "xenosinjector.exe":      "medium",
}

SUSPICIOUS_DOMAINS = {
    "wearedevs.net":        "high",
    "krnl.cat":             "high",
    "krnl.place":           "high",
    "krnl.ca":              "high",
    "getfluxus.com":        "high",
    "fluxteam.net":         "high",
    "getsolara.dev":        "high",
    "solara.gg":            "high",
    "wave.cx":              "high",
    "getwave.gg":           "high",
    "velocityexploit.com":  "high",
    "electron.dev":         "high",
    "sentinel.gg":          "high",
    "trigonevo.com":        "high",
    "argonexec.com":        "high",
    "awp.gg":               "high",
    "zorara.cc":            "high",
    "swift.lat":            "high",
    "nezur.cc":             "high",
    "hydrogen.lat":         "high",
    "codex.lol":            "high",
    "arceusx.net":          "high",
    "arceusx.com":          "high",
    "delta-executor.com":   "high",
    "deltaexploits.gg":     "high",
    "scriptware.com":       "high",
    "evonexecutor.com":     "high",
    "v3rmillion.net":       "medium",
    "rscripts.net":         "low",
    "scriptblox.com":       "low",
    "robloxscripts.com":    "low",
}

SUSPICIOUS_FOLDER_NAMES = {
    "synapse x":            "high",
    "synapsex":             "high",
    "krnl":                 "high",
    "fluxus":               "high",
    "wave":                 "high",
    "solara":               "high",
    "velocity executor":    "high",
    "electron":             "high",
    "sentinel":             "high",
    "trigon evo":           "high",
    "argon":                "high",
    "hydrogen":             "high",
    "codex":                "high",
    "jjsploit":             "high",
    "scriptware":           "high",
    "rbxexploits":          "high",
    "robloxscripts":        "medium",
    "roblox scripts":       "medium",
    "exploits":             "low",
}

PATHS_TO_SCAN_FOR_EXECUTORS = [
    r"%USERPROFILE%",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\AppData\Local",
    r"%USERPROFILE%\AppData\Roaming",
    r"%USERPROFILE%\AppData\LocalLow",
    r"%LOCALAPPDATA%\Programs",
    r"%PROGRAMFILES%",
    r"%PROGRAMFILES(X86)%",
]

BROWSER_HISTORY_DBS = [
    (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History", "Chrome"),
    (r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 1\History", "Chrome P1"),
    (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History", "Edge"),
    (r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History", "Brave"),
    (r"%APPDATA%\Opera Software\Opera Stable\History", "Opera"),
    (r"%APPDATA%\Opera Software\Opera GX Stable\History", "Opera GX"),
]

ROBLOX_LOG_PATHS = [
    r"%LOCALAPPDATA%\Roblox\logs",
    r"%TEMP%\Roblox",
]

ROBLOX_LOG_PATTERNS = [
    "DllInjection",
    "module injected",
    "Hyperion",
    "AntiTamper",
    "ProcessUntrusted",
    "RBXCRASH",
]

# ----------------------------- Anti-evasão -----------------------------

VM_PROCESS_NAMES = {
    "vmtoolsd.exe":      "VMware Tools",
    "vmwaretray.exe":    "VMware",
    "vmwareuser.exe":    "VMware",
    "vboxservice.exe":   "VirtualBox",
    "vboxtray.exe":      "VirtualBox",
    "vboxcontrol.exe":   "VirtualBox",
    "qemu-ga.exe":       "QEMU",
    "xenservice.exe":    "Xen",
    "prl_tools.exe":     "Parallels",
    "prl_cc.exe":        "Parallels",
}

SANDBOX_PROCESS_NAMES = {
    "sbiesvc.exe":       "Sandboxie",
    "sbiectrl.exe":      "Sandboxie",
    "sandboxierpcss.exe":"Sandboxie",
    "cuckoo.exe":        "Cuckoo Sandbox",
    "wireshark.exe":     "Wireshark (análise)",
    "fiddler.exe":       "Fiddler (proxy)",
    "procmon.exe":       "Process Monitor",
    "procmon64.exe":     "Process Monitor",
}

VM_REGISTRY_PROBES = [
    # (subkey, value_name, substring_que_indica_vm, label)
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "vmware",      "VMware"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "innotek",     "VirtualBox"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "qemu",        "QEMU"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "parallels",   "Parallels"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemProductName",  "virtual",     "VM (genérica)"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "BIOSVendor",         "vmware",      "VMware"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "BIOSVendor",         "innotek",     "VirtualBox"),
]

VM_SERVICE_NAMES = [
    "vmci", "vmhgfs", "vmmemctl", "vmmouse", "vmrawdsk", "vmusbmouse", "vmx86",
    "vboxguest", "vboxmouse", "vboxservice", "vboxsf", "vboxvideo",
    "xenevtchn", "xennet", "xenservice", "xenvbd",
    "prl_eth5", "prl_fs", "prl_memdev", "prl_tg", "prl_time",
]

VM_MAC_PREFIXES = {
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "00:03:FF": "Microsoft Hyper-V",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    "52:54:00": "QEMU/KVM",
}

# ----------------------------- Scripts Lua/Luau -----------------------------

SCRIPT_SEARCH_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\AppData\Roaming",
    r"%USERPROFILE%\AppData\Local",
    r"%LOCALAPPDATA%\Roblox",
]

SCRIPT_SEARCH_MAX_DEPTH = 4
SCRIPT_EXTENSIONS = (".lua", ".luau", ".txt")

SCRIPT_RED_FLAGS = {
    "loadstring(":          "high",
    "getrawmetatable":      "high",
    "setreadonly":          "high",
    "sethiddenproperty":    "high",
    "gethiddenproperty":    "high",
    "hookfunction":         "high",
    "hookmetamethod":       "high",
    "getconnections":       "high",
    "remotespy":            "high",
    "infinite jump":        "medium",
    "infinitejump":         "medium",
    "fly script":           "medium",
    "aimbot":               "high",
    "esp script":           "high",
    "wallhack":             "high",
    "noclip":               "medium",
    "speed hack":           "high",
    "speedhack":            "high",
    "owl hub":              "high",
    "dark hub":             "high",
    "infinite yield":       "high",
    "infiniteyield":        "high",
    "rconsoleprint":        "medium",
    "queue_on_teleport":    "medium",
    "syn.request":          "high",
    "http_request":         "medium",
    "getgenv()":            "high",
    "getsenv":              "medium",
    "getrenv":              "medium",
    "fireserver":           "low",
    "writefile(":           "low",
}

# ----------------------------- Cleaners / Anti-forensics -----------------------------

CLEANER_NAMES = {
    "bleachbit":        "high",
    "privazer":         "high",
    "ccleaner":         "medium",
    "ccleaner.exe":     "medium",
    "wise disk cleaner":"medium",
    "wise registry cleaner":"medium",
    "advanced systemcare":"medium",
    "cleanmypc":        "medium",
    "kcleaner":         "medium",
    "iobit uninstaller":"medium",
    "revo uninstaller": "medium",
    "wipe":             "medium",
    "eraser":           "high",
    "sdelete":          "high",
    "shred":            "high",
    "usnjrnl delete":   "high",
    "fsutil usn deletejournal": "high",
}

# ----------------------------- Bloxstrap / Bytecode -----------------------------

BLOXSTRAP_PATHS = [
    r"%LOCALAPPDATA%\Bloxstrap",
    r"%LOCALAPPDATA%\Bloxstrap\Modifications",
    r"%LOCALAPPDATA%\Bloxstrap\Versions",
]

BYTECODE_DUMP_FOLDERS = [
    r"%USERPROFILE%\Desktop\scripts",
    r"%USERPROFILE%\Desktop\roblox scripts",
    r"%USERPROFILE%\Documents\scripts",
    r"%USERPROFILE%\Documents\roblox",
    r"%USERPROFILE%\Documents\roblox scripts",
    r"%LOCALAPPDATA%\Roblox\Modules",
    r"%APPDATA%\Krnl\autoexec",
    r"%APPDATA%\Krnl\scripts",
    r"%APPDATA%\Wave\autoexec",
    r"%APPDATA%\Solara\autoexec",
    r"%APPDATA%\Fluxus\autoexec",
    r"%APPDATA%\Hydrogen\autoexec",
]

# ----------------------------- Hidden files / persistence -----------------------------

HIDDEN_FILE_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\AppData\Local",
    r"%USERPROFILE%\AppData\Roaming",
]

AUTOSTART_REGISTRY_KEYS_HKCU = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Run"),
]

AUTOSTART_REGISTRY_KEYS_HKLM = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (Wow64)"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Run"),
]

STARTUP_FOLDERS = [
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
]

WER_PATHS = [
    r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive",
    r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue",
    r"%PROGRAMDATA%\Microsoft\Windows\WER\ReportArchive",
    r"%PROGRAMDATA%\Microsoft\Windows\WER\ReportQueue",
]
