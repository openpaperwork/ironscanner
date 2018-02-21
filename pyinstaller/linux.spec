# -*- mode: python -*-

import os
import sys

block_cipher = None

BASE_PATH = os.getcwd()

print("BASEPATH: {}".format(BASE_PATH))

datas = []
for (dirpath, subdirs, filenames) in os.walk(BASE_PATH):
    shortdirpath = dirpath[len(BASE_PATH):]
    if ("dist" in shortdirpath.lower()
            or "build" in shortdirpath.lower()
            or "egg" in shortdirpath.lower()
            or "tox" in shortdirpath.lower()):
        continue
    for filename in filenames:
        if filename.lower().endswith(".png") and shortdirpath.lower().endswith("doc"):
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
        print(
            "=== Adding file [{}] --> [{}] ===".format(filepath, dest)
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
          upx=False,
          runtime_tmpdir=None,
          console=True)
