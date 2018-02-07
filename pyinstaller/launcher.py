#!/usr/bin/python3

import multiprocessing
import os
import sys

from ironscanner import main

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        multiprocessing.freeze_support()

    main.main()
