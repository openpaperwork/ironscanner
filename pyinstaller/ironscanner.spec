# -*- mode: python -*-

import os
import sys

block_cipher = None

BASE_PATH = os.getcwd()

datas = []
for (dirpath, subdirs, filenames) in os.walk(BASE_PATH):
    if ("dist" in dirpath.lower()
            or "build" in dirpath.lower()
            or "egg" in dirpath.lower()
            or "tox" in dirpath.lower()):
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
                and not filename.lower().endswith(".txt")
                and not filename.lower().endswith(".pdf")):
            continue
        filepath = os.path.join(dirpath, filename)

        dest = "data"
        sys.stderr.write(
            "=== Adding file [{}] --> [{}] ===\n".format(filepath, dest)
        )
        datas.append((filepath, dest))

a = Analysis(['launcher.py'],
             pathex=[],
             binaries=[],
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
          cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='ironscanner',
          debug=True,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True)
