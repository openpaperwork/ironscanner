#!/usr/bin/env python3

import logging

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib
from gi.repository import Gtk

import pyinsane2

from . import util


logger = logging.getLogger(__name__)


class PersonalDialog(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree
        widget_tree.get_object("checkboxAcceptContact").connect(
            "toggled", self._on_accept_contact_changed
        )

    def _on_accept_contact_changed(self, button):
        widgets = [
            self.widget_tree.get_object("labelUserName"),
            self.widget_tree.get_object("entryUserName"),
            self.widget_tree.get_object("labelUserEmail"),
            self.widget_tree.get_object("entryUserEmail"),
        ]
        for widget in widgets:
            widget.set_sensitive(not widget.get_sensitive())



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



def main():
    pyinsane2.init()

    try:
        main_loop = GLib.MainLoop()

        application = Gtk.Application()

        widget_tree = util.load_uifile("mainform.glade")

        PersonalDialog(widget_tree)
        ScannerSettings(widget_tree)
        TestPresentation(widget_tree)
        ScanTest(widget_tree)
        PhotoSelector(widget_tree)
        UserComment(widget_tree)
        ReportSender(widget_tree)

        mainform = widget_tree.get_object("mainform")
        mainform.connect("close", lambda w: main_loop.quit())
        mainform.connect("escape", lambda w: main_loop.quit())
        mainform.connect("cancel", lambda w: main_loop.quit())
        mainform.show_all()

        application.add_window(mainform)

        main_loop.run()
    finally:
        pyinsane2.exit()


if __name__ == "__main__":
    main()
