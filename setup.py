#!/usr/bin/env python3

from setuptools import (
    find_packages,
    setup,
)

setup(
    name="ironscanner",
    # Before releasing a new version:
    # * update the download_url in this file
    # * update the ChangeLog file
    # * update flatpak/work.openpaper.IronScanner.appdata.xml:<releases>
    #
    # Release:
    # * commit
    # * tag
    # * python3 ./setup.py sdist upload
    #
    # After the release:
    # * add a file flatpak/<version>.json
    # * update flatpak/release.json
    version="1.0",
    description=(
        "Scanner information collector"
    ),
    long_description="""Collect as much information as possible regarding
    image scanners.""",
    keywords="scanner gui",
    url="https://github.com/openpaperwork/ironscanner",
    download_url=("https://github.com/openpaperwork/ironscanner"
                  "/archive/1.0.tar.gz"),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: X11 Applications :: GTK",
        "Environment :: X11 Applications :: Gnome",
        "Intended Audience :: End Users/Desktop",
        ("License :: OSI Approved ::"
         " GNU General Public License v3 or later (GPLv3+)"),
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Multimedia :: Graphics :: Capture :: Scanners",
    ],
    license="GPLv3+",
    author="Jerome Flesch",
    author_email="jflesch@openpaper.work",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    entry_points={
        'gui_scripts': [
            'ironscanner = ironscanner:main',
        ]
    },
    zip_safe=True,
    install_requires=[
        "Pillow",
        "pyinsane2",
    ]
)
