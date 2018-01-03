#!/usr/bin/env python3

import logging
import multiprocessing
import os
import threading

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GdkPixbuf
from gi.repository import GLib
from gi.repository import Gtk

import pyinsane2

from . import dummy
from . import log
from . import trace
from . import util


logger = logging.getLogger(__name__)


g_log_tracker = log.LogTracker()


class ScannerFinder(threading.Thread):
    def __init__(self, cb):
        super().__init__(name="ScannerFinder")
        self.cb = cb

    def run(self):
        logger.info("Looking for scanners ...")
        scanners = trace.trace(pyinsane2.get_devices)
        logger.info("{} scanners found".format(len(scanners)))
        GLib.idle_add(self.cb, scanners)


class PersonalInfo(object):
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
            sensitive = not widget.get_sensitive()
            widget.set_sensitive(sensitive)
            if not sensitive:
                widget.set_text("")

    def get_user_info(self):
        return {
            "user_name":
            self.widget_tree.get_object("entryUserName").get_text(),
            "user_email":
            self.widget_tree.get_object("entryUserEmail").get_text(),
        }


class ScannerSettings(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree
        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )
        widget_tree.get_object("comboboxDevices").connect(
            "changed", self._on_scanner_selected
        )
        widget_tree.get_object("comboboxScannerTypes").connect(
            "changed", self._on_scanner_type_selected
        )
        self.scanners = {}

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageTestSettings"):
            return
        ScannerFinder(self._on_scanners_get).start()

    def _on_scanners_get(self, scanners):
        self.widget_tree.get_object("mainform").set_page_complete(
            self.widget_tree.get_object("pageTestSettings"),
            True
        )

        liststore = self.widget_tree.get_object("liststoreDevices")
        for scanner in scanners:
            username = "{} {} ({})".format(
                scanner.vendor, scanner.model, scanner.nice_name
            )
            self.scanners[scanner.name] = scanner
            logger.info("{} -> {}".format(scanner.name, username))
            liststore.append((username, scanner.name))
        combobox = self.widget_tree.get_object("comboboxDevices")
        combobox.set_model(liststore)
        combobox.set_sensitive(True)
        combobox.set_active(0)

    @staticmethod
    def _get_resolutions(resolutions):
        # Sometimes sane return the resolutions as a integer array,
        # sometimes as a range (-> tuple). So if it is a range, we turn
        # it into an array
        if not isinstance(resolutions, tuple):
            return resolutions

        interval = resolutions[2]
        if interval < 25:
            interval = 25
        return range(resolutions[0], resolutions[1] + 1, interval)

    def _on_scanner_selected(self, combobox):
        scanner = self.get_scanner()

        logger.info("Selected scanner: {}".format(scanner.name))

        for opt in scanner.options.values():
            logger.info("  Option: %s", opt.name)
            logger.info("    Title: %s", opt.title)
            logger.info("    Desc: %s", opt.desc)
            logger.info("    Type: %s", str(opt.val_type))
            logger.info("    Unit: %s", str(opt.unit))
            logger.info("    Size: %d", opt.size)
            logger.info("    Capabilities: %s", str(opt.capabilities))
            logger.info("    Constraint type: %s", str(opt.constraint_type))
            logger.info("    Constraint: %s", str(opt.constraint))
            try:
                logger.info("    Value: %s", str(opt.value))
            except pyinsane2.PyinsaneException as exc:
                # Some scanner allow changing a value, but not reading it.
                # For instance Canon Lide 110 allow setting the resolution,
                # but not reading it
                logger.info("    Value: Failed to get the value: %s",
                            str(exc))

        sources = self.widget_tree.get_object("liststoreSources")
        resolutions = self.widget_tree.get_object("liststoreResolutions")
        modes = self.widget_tree.get_object("liststoreModes")

        for source in scanner.options['source'].constraint:
            sources.append((source, source))
        for resolution in self._get_resolutions(
                    scanner.options['resolution'].constraint
                ):
            resolutions.append((str(resolution), resolution))
        for mode in scanner.options['mode'].constraint:
            modes.append((mode, mode))

        lists = [
            (
                self.widget_tree.get_object("comboboxScannerTypes"),
                self.widget_tree.get_object("liststoreScannerTypes"),
            ),
            (
                self.widget_tree.get_object("comboboxSources"),
                self.widget_tree.get_object("liststoreSources"),
            ),
            (
                self.widget_tree.get_object("comboboxResolutions"),
                self.widget_tree.get_object("liststoreResolutions"),
            ),
            (
                self.widget_tree.get_object("comboboxModes"),
                self.widget_tree.get_object("liststoreModes"),
            ),
        ]
        for (combobox, liststore) in lists:
            combobox.set_model(liststore)
            combobox.set_sensitive(True)
            combobox.set_active(0)

    def _on_scanner_type_selected(self, combobox):
        types = self.widget_tree.get_object("liststoreScannerTypes")
        img_file = types[combobox.get_active()][2]
        img_widget = self.widget_tree.get_object("imageScanner")
        if img_file is None or img_file == "":
            img_widget.set_from_icon_name("gtk-missing-image",
                                          Gtk.IconSize.DIALOG)
        else:
            pixbuf = util.load_pixbuf(img_file)
            (pw, ph) = (pixbuf.get_width(), pixbuf.get_height())
            rect = img_widget.get_allocation()
            ratio = max(pw / rect.width, pw / rect.height)
            pixbuf = pixbuf.scale_simple(int(pw / ratio), int(ph / ratio),
                                         GdkPixbuf.InterpType.BILINEAR)
            img_widget.set_from_pixbuf(pixbuf)

    def get_scanner(self):
        liststore = self.widget_tree.get_object("liststoreDevices")
        active = self.widget_tree.get_object("comboboxDevices").get_active()
        if active < 0 or active >= len(liststore):
            return dummy.DummyScanner()
        devid = liststore[active][1]
        scanner = self.scanners[devid]
        return scanner

    def configure_scanner(self, scanner):
        trace.trace(
            setattr, scanner.options['source'], 'value',
            self.widget_tree.get_object('liststoreSources')[
                self.widget_tree.get_object('comboboxSources').get_active()
            ][1]
        )
        trace.trace(
            setattr, scanner.options['resolution'], 'value',
            self.widget_tree.get_object('liststoreResolutions')[
                self.widget_tree.get_object('comboboxResolutions').get_active()
            ][1]
        )
        trace.trace(
            setattr, scanner.options['mode'], 'value',
            self.widget_tree.get_object('liststoreModes')[
                self.widget_tree.get_object('comboboxModes').get_active()
            ][1]
        )

    def get_user_info(self):
        active = self.widget_tree.get_object("comboboxDevices").get_active()
        liststore = self.widget_tree.get_object("liststoreDevices")
        if active < 0 or active >= len(liststore):
            scanner = dummy.DummyScanner()
            src = "None"
            resolution = 0
            mode = "None"
            dev_type = "None"
        else:
            scanner = self.get_scanner()
            src = self.widget_tree.get_object('liststoreSources')[
                self.widget_tree.get_object('comboboxSources').get_active()
            ][1]
            resolution = self.widget_tree.get_object('liststoreResolutions')[
                self.widget_tree.get_object('comboboxResolutions').get_active()
            ][1]
            mode = self.widget_tree.get_object('liststoreModes')[
                self.widget_tree.get_object('comboboxModes').get_active()
            ][1]
            dev_type = self.widget_tree.get_object('liststoreScannerTypes')[
                self.widget_tree.get_object('comboboxScannerTypes').get_active()
            ][1]
        info = {
            "dev_name": "{} {} ({})".format(
                scanner.vendor, scanner.model, scanner.nice_name
            ),
            "dev_source": src,
            "dev_resolution": resolution,
            "dev_mode": mode,
            "dev_type": dev_type,
        }
        return info


class SysInfo(object):
    def get_user_info(self):
        return {
            # TODO: more
            'sys_type': os.name,
            'sys_proc': multiprocessing.cpu_count(),
        }


class TestSummary(object):
    TEMPLATE = """
Personal information that will be attached to the report:
- Name: {user_name}
- Email: {user_email}

System informations:
- OS type: {sys_type}
- Processors: {sys_proc}

Summary of the test:
- Scanner: {dev_name}
- Type: {dev_type}
- Source: {dev_source}
- Resolutions: {dev_resolution}
- Mode: {dev_mode}
    """

    def __init__(self, widget_tree, sources):
        self.widget_tree = widget_tree
        self.sources = sources

        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageSummary"):
            return
        logger.info("Preparing summary")
        values = {}
        for src in self.sources:
            values.update(src.get_user_info())
        content = self.TEMPLATE.format(**values).strip()
        summary = self.widget_tree.get_object("textbufferSummary")
        summary.set_text(content)
        logger.info("Summary ready")
        logger.info(content)


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
    trace.trace(pyinsane2.init)
    logger.info("Pyinsane2 ready")

    try:
        main_loop = GLib.MainLoop()

        application = Gtk.Application()

        widget_tree = util.load_uifile("mainform.glade")

        MainForm(application, main_loop, widget_tree)
        user_info = PersonalInfo(widget_tree)
        scan_settings = ScannerSettings(widget_tree)
        sys_info = SysInfo()
        TestSummary(widget_tree, [user_info, scan_settings, sys_info])
        ScanTest(widget_tree)
        PhotoSelector(widget_tree)
        UserComment(widget_tree)
        ReportSender(widget_tree)

        application.register()

        main_loop.run()
        logger.info("Quitting")
    finally:
        logger.info("Exiting Pyinsane2")
        pyinsane2.exit()
    logger.info("Good bye")


if __name__ == "__main__":
    main()
