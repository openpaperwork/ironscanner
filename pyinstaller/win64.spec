# -*- mode: python -*-

import os
import site
import sys

block_cipher = None

BASE_PATH = os.getcwd()

# Pyinstaller misses some .dll (GObject & co) --> we have to request them
# explicitly
typelib_path = os.path.join(
    site.getsitepackages()[1], 'gnome', 'lib', 'girepository-1.0'
)
bins = [
    (os.path.join(typelib_path, tl), 'gi_typelibs')
    for tl in os.listdir(typelib_path)
]
lib_path = os.path.join(site.getsitepackages()[1], 'gnome')
extra_libs = [
    (os.path.join(lib_path, 'libpoppler-glib-8.dll'), '.'),
    (os.path.join(lib_path, 'liblcms2-2.dll'), '.'),
    (os.path.join(lib_path, 'libnotify-4.dll'), '.'),
    (os.path.join(lib_path, 'libopenjp2.dll'), '.'),
    (os.path.join(lib_path, 'libstdc++.dll'), '.'),
]
sys.stderr.write("=== Adding extra libs: ===\n{}\n===\n".format(extra_libs))
bins += extra_libs

# We also have to add data files
datas = []
for (dirpath, subdirs, filenames) in os.walk(BASE_PATH):
    if ("dist" in dirpath.lower()
            or "build" in dirpath.lower()
            or "egg" in dirpath.lower()):
        continue
    for filename in filenames:
        if filename.lower().endswith(".png") and dirpath.lower().endswith("doc"):
            continue
        if (not filename.lower().endswith(".ico")
                and not filename.lower().endswith(".png")
                and not filename.lower().endswith(".svg")
                and not filename.lower().endswith(".xml")
                and not filename.lower().endswith(".glade")
                and not filename.lower().endswith(".css")
                and not filename.lower().endswith(".mo")
                and not filename.lower().endswith(".pdf")
                and not filename.lower().endswith(".txt")):
            continue
        filepath = os.path.join(dirpath, filename)

        dest = "data"
        sys.stderr.write(
            "=== Adding file [{}] --> [{}] ===\n".format(filepath, dest)
        )
        datas.append((filepath, dest))

a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=bins,
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='ironscanner',
    debug=True,
    strip=False,
    upx=False,
    console=True
)
