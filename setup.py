#!/usr/bin/env python3

from setuptools import (
    find_packages,
    setup,
)


try:
    with open("src/ironscanner/version.txt", "r") as file_descriptor:
        version = file_descriptor.read().strip()
        if "-" in version:
            version = version.split("-")[0]
except FileNotFoundError:
    print("WARNING: version.txt file is missing")
    print("WARNING: Please run 'make' first")
    version = "0.0.1"


setup(
    name="ironscanner",
    # Before releasing a new version:
    # * update the download_url in this file
    # * update the ChangeLog file
    # * update src/ironscanner/main.py:__version__
    # * update flatpak/work.openpaper.IronScanner.appdata.xml:<releases>
    #
    # Release:
    # * commit
    # * tag
    version=version,
    description=(
        "Scanner information collector"
    ),
    long_description=(
        "Collect as much information as possible regarding"
        " image scanners."
    ),
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
            'ironscanner = ironscanner.main:main',
        ]
    },
    zip_safe=True,
    install_requires=[
        "Pillow",
        "pyinsane2",
        "psutil",
    ]
)
