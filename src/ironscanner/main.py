#!/usr/bin/env python3

import logging
import threading

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib
from gi.repository import Gtk

import pyinsane2

from . import log
from . import trace
from . import util


logger = logging.getLogger(__name__)


g_log_tracker = log.LogTracker()
g_scanners = {}


class ScannerFinder(threading.Thread):
    def __init__(self, cb):
        super().__init__(name="ScannerFinder")
        self.cb = cb

    def run(self):
        logger.info("Looking for scanners ...")
        scanners = trace.trace(pyinsane2.get_devices)
        logger.info("{} scanners found".format(len(scanners)))
        GLib.idle_add(self.cb, scanners)


class TestSettings(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree
        widget_tree.get_object("checkboxAcceptContact").connect(
            "toggled", self._on_accept_contact_changed
        )
        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageTestSettings"):
            return
        ScannerFinder(self._on_scanner_get).start()

    def _on_accept_contact_changed(self, button):
        widgets = [
            self.widget_tree.get_object("labelUserName"),
            self.widget_tree.get_object("entryUserName"),
            self.widget_tree.get_object("labelUserEmail"),
            self.widget_tree.get_object("entryUserEmail"),
        ]
        for widget in widgets:
            widget.set_sensitive(not widget.get_sensitive())

    def _on_scanner_get(self, scanners):
        liststore = self.widget_tree.get_object("liststoreDevices")
        for scanner in scanners:
            username = "{} {} ({})".format(
                scanner.vendor, scanner.model, scanner.nice_name
            )
            g_scanners[scanner.name] = scanner
            logger.info("{} -> {}".format(scanner.name, username))
            liststore.append((username, scanner.name))
        combobox = self.widget_tree.get_object("comboboxDevices")
        combobox.set_model(liststore)
        combobox.set_sensitive(True)
        combobox.set_active(0)


class ScannerSettings(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class TestPresentation(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class ScanTest(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class PhotoSelector(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class UserComment(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class ReportSender(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree


class MainForm(object):
    def __init__(self, application, main_loop, widget_tree):
        self.application = application
        self.main_loop = main_loop
        self.widget_tree = widget_tree

        self.application.connect("startup", self.init_mainform)

    def init_mainform(self, *args, **kwargs):
        mainform = self.widget_tree.get_object("mainform")
        mainform.set_icon(util.load_pixbuf("logo.png"))
        mainform.connect("close", lambda w: self.main_loop.quit())
        mainform.connect("escape", lambda w: self.main_loop.quit())
        mainform.connect("cancel", lambda w: self.main_loop.quit())
        mainform.show_all()

        self.application.add_window(mainform)


def main():
    g_log_tracker.init()

    logger.info("Initializing pyinsane2 ...")
    pyinsane2.init()
    logger.info("Pyinsane2 ready")

    try:
        main_loop = GLib.MainLoop()

        application = Gtk.Application()

        widget_tree = util.load_uifile("mainform.glade")

        MainForm(application, main_loop, widget_tree)
        TestSettings(widget_tree)
        ScannerSettings(widget_tree)
        TestPresentation(widget_tree)
        ScanTest(widget_tree)
        PhotoSelector(widget_tree)
        UserComment(widget_tree)
        ReportSender(widget_tree)

        application.register()

        main_loop.run()
    finally:
        pyinsane2.exit()


if __name__ == "__main__":
    main()
