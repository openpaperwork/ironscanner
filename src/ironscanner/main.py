#!/usr/bin/env python3

import base64
import http.client
import io
import json
import logging
import multiprocessing
import os
import platform
import ssl
import sys
import threading

import PIL
import psutil
import pyinsane2

import gi
gi.require_version('GdkPixbuf', '2.0')
gi.require_version('Gtk', '3.0')

from gi.repository import GdkPixbuf  # noqa: E402
from gi.repository import GLib  # noqa: E402
from gi.repository import Gtk  # noqa: E402

from . import dummy  # noqa: E402
from . import log  # noqa: E402
from . import trace  # noqa: E402
from . import util  # noqa: E402


logger = logging.getLogger(__name__)


g_log_tracker = log.LogTracker()


TARGET_PROTOCOL = os.getenv("TARGET_PROTOCOL", "https")
TARGET_HOST = os.getenv("TARGET_HOST", "openpaper.work")
TARGET_PATH = os.getenv("TARGET_PATH", "/scannerdb/post")
USER_AGENT = "IronScanner"
SSL_CONTEXT = ssl._create_unverified_context()

__version__ = "N/A"


class Greeting(object):
    def __init__(self, widget_tree):
        global __version__
        try:
            __version__ = util.load_text("version.txt")
        except FileNotFoundError:
            logger.warning("version.txt file is missing")
            logger.warning("Please run 'make' first")
            __version__ = "unknown"
        widget_tree.get_object("ironscannerVersionLabel").set_text(
            "IronScanner {}".format(__version__)
        )


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


class LogHandler(logging.Handler):
    MAX_DISPLAYED_LINES = 1000
    MAX_MEM_LINES = 10000

    def __init__(self, txt_buffer=None, scrollbars=None,
                 log_level=logging.INFO):
        super().__init__()
        self._formatter = logging.Formatter('%(levelname)-6s %(message)s')
        self.output_lines = []
        self.buf = txt_buffer
        if scrollbars is not None:
            self.scrollbar = scrollbars.get_vadjustment()
        else:
            self.scrollbar = None
        self.log_level = log_level

    def enable(self):
        l = logging.getLogger()
        l.addHandler(self)

    def disable(self):
        self.flush()
        l = logging.getLogger()
        l.removeHandler(self)

    def validate(self):
        self.output_lines.append("All done !")
        GLib.idle_add(self._update_buffer)

    def emit(self, record):
        if record.levelno < self.log_level:
            return
        line = self._formatter.format(record)
        self.output_lines.append(line)
        if len(self.output_lines) > self.MAX_MEM_LINES:
            self.output_lines.pop(0)

        if self.buf is not None:
            GLib.idle_add(self._update_buffer)

    def _update_buffer(self):
        self.buf.set_text("\n".join(self.output_lines))
        self.scrollbar.set_value(self.scrollbar.get_upper())

    def get_logs(self):
        return self.output_lines


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

    def __str__(self):
        return "User info"

    def _on_accept_contact_changed(self, button):
        widgets = [
            (self.widget_tree.get_object("labelUserName"), False),
            (self.widget_tree.get_object("entryUserName"), True),
            (self.widget_tree.get_object("labelUserEmail"), False),
            (self.widget_tree.get_object("entryUserEmail"), True),
        ]
        for (widget, clear) in widgets:
            sensitive = not widget.get_sensitive()
            widget.set_sensitive(sensitive)
            if clear and not sensitive:
                widget.set_text("")

    def get_user_info(self):
        return {
            "user_name":
            self.widget_tree.get_object("entryUserName").get_text(),
            "user_email":
            self.widget_tree.get_object("entryUserEmail").get_text(),
        }

    def complete_report(self, report):
        if 'user' not in report:
            report['user'] = {}
        report['user']['name'] = (
            self.widget_tree.get_object("entryUserName").get_text()
        )
        report['user']['email'] = (
            self.widget_tree.get_object("entryUserEmail").get_text()
        )


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
        self.options = {}

    def __str__(self):
        return "Scanner settings"

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageTestSettings"):
            return
        ScannerFinder(self._on_scanners_get).start()
        self._on_scanner_type_selected(self.widget_tree.get_object(
            "comboboxScannerTypes"
        ))

    def _on_scanners_get(self, scanners):
        self.widget_tree.get_object("mainform").set_page_complete(
            self.widget_tree.get_object("pageTestSettings"),
            True
        )

        liststore = self.widget_tree.get_object("liststoreDevices")
        liststore.clear()
        self.scanners = {}
        for scanner in scanners:
            username = "{} {} ({})".format(
                scanner.vendor, scanner.model, scanner.nice_name
            )
            self.scanners[scanner.name] = scanner
            logger.info("{} -> {}".format(scanner.name, username))
            liststore.append((username, scanner.name))

        liststore.append(("Not in the list", None))

        combobox = self.widget_tree.get_object("comboboxDevices")
        combobox.set_model(liststore)
        combobox.set_sensitive(True)
        combobox.set_active(0)
        self.widget_tree.get_object("labelDevices").set_sensitive(True)

    @staticmethod
    def _get_resolutions(resolutions):
        MAX_CHOICES = 30
        # Sometimes sane return the resolutions as a integer array,
        # sometimes as a range (-> tuple). So if it is a range, we turn
        # it into an array
        if not isinstance(resolutions, tuple):
            return resolutions

        interval = resolutions[2]
        if interval < 25:
            interval = 25
        if (resolutions[1] - resolutions[0]) / interval > MAX_CHOICES:
            # limit the choices
            new_interval = int((resolutions[1] - resolutions[0]) / MAX_CHOICES)
            new_interval -= new_interval % interval
            logger.info("Resolution interval adjusted: {} --> {}".format(
                interval, new_interval
            ))
            interval = new_interval
        return range(resolutions[0], resolutions[1] + 1, interval)

    def _set_scanner_selected(self, scanner=None):
        lists = [
            (
                self.widget_tree.get_object("comboboxSources"),
                self.widget_tree.get_object("liststoreSources"),
                self.widget_tree.get_object("labelSources"),
            ),
            (
                self.widget_tree.get_object("comboboxResolutions"),
                self.widget_tree.get_object("liststoreResolutions"),
                self.widget_tree.get_object("labelResolutions"),
            ),
            (
                self.widget_tree.get_object("comboboxModes"),
                self.widget_tree.get_object("liststoreModes"),
                self.widget_tree.get_object("labelModes"),
            ),
        ]
        for (combobox, liststore, label) in lists:
            combobox.set_model(liststore)
            combobox.set_sensitive(scanner is not None)
            combobox.set_active(0)
            label.set_sensitive(scanner is not None)

        self.widget_tree.get_object("labelManufacturer").set_sensitive(
            scanner is None
        )
        self.widget_tree.get_object("entryManufacturer").set_sensitive(
            scanner is None
        )
        self.widget_tree.get_object("labelModel").set_sensitive(
            scanner is None
        )
        self.widget_tree.get_object("entryModel").set_sensitive(
            scanner is None
        )
        self.widget_tree.get_object("entryManufacturer").set_text(
            scanner.vendor if scanner is not None else ""
        )
        self.widget_tree.get_object("entryModel").set_text(
            scanner.model if scanner is not None else ""
        )

        if scanner is None:
            self.widget_tree.get_object("expanderScannerInfo").set_expanded(
                True
            )
            self.widget_tree.get_object("entryManufacturer").grab_focus()
            GLib.idle_add(self._scroll_down)

    def _scroll_down(self):
        vadj = self.widget_tree.get_object(
            "pageTestSettings").get_vadjustment()
        vadj.set_value(vadj.get_upper())

    def _on_scanner_selected(self, combobox):
        scanner = self.get_scanner()

        self._set_scanner_selected(scanner)
        if scanner is None:
            return

        logger.info("Selected scanner: {}".format(scanner.name))

        self.options = {}
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
            value = ""
            try:
                value = str(opt.value)
            except pyinsane2.PyinsaneException as exc:
                value = "(Exception: {})".format(str(exc))
            logger.info("    Value: %s", value)
            self.options[opt.name] = {
                'title': str(opt.title),
                'desc': str(opt.desc),
                'type': str(opt.val_type),
                'unit': str(opt.unit),
                'size': str(opt.size),
                'capabilities': str(opt.capabilities),
                'contrainttype': str(opt.constraint_type),
                'constraint': str(opt.constraint),
                'initial_value': value
            }

        sources = self.widget_tree.get_object("liststoreSources")
        sources.clear()
        resolutions = self.widget_tree.get_object("liststoreResolutions")
        resolutions.clear()
        modes = self.widget_tree.get_object("liststoreModes")
        modes.clear()

        for source in scanner.options['source'].constraint:
            sources.append((source, source))
        for resolution in self._get_resolutions(
                    scanner.options['resolution'].constraint
                ):
            txt = str(resolution)
            if resolution == 150:
                txt += " (recommended)"
            resolutions.append((txt, resolution))
        for mode in scanner.options['mode'].constraint:
            txt = mode
            if mode.lower() == "color":
                txt += " (recommended)"
            modes.append((txt, mode))

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

    def get_scanner_id(self):
        liststore = self.widget_tree.get_object("liststoreDevices")
        active = self.widget_tree.get_object("comboboxDevices").get_active()
        if active < 0 or active >= len(liststore):
            return dummy.DummyScanner()
        return liststore[active][1]

    def get_scanner(self):
        devid = self.get_scanner_id()
        if devid is None:
            return devid
        scanner = self.scanners[devid]
        return scanner

    def get_scanner_config(self):
        source_idx = (
            self.widget_tree.get_object('comboboxSources').get_active()
        )
        resolution_idx = (
            self.widget_tree.get_object('comboboxResolutions').get_active()
        )
        mode_idx = (
            self.widget_tree.get_object('comboboxModes').get_active()
        )
        if source_idx < 0 or resolution_idx < 0 or mode_idx < 0:
            return {}
        return {
            'source': self.widget_tree.get_object('liststoreSources')[
                source_idx
            ][1],
            'resolution': self.widget_tree.get_object('liststoreResolutions')[
                resolution_idx
            ][1],
            'mode': self.widget_tree.get_object('liststoreModes')[
                mode_idx
            ][1],
        }

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
                self.widget_tree.get_object('comboboxScannerTypes')
                .get_active()
            ][1]
        vendor = self.widget_tree.get_object("entryManufacturer").get_text()
        model = self.widget_tree.get_object("entryModel").get_text()
        nice_name = (
            scanner.nice_name
            if scanner is not None else
            "{} {}".format(vendor, model)
        )
        info = {
            "dev_name": "{} {} ({})".format(vendor, model, nice_name),
            "dev_source": src,
            "dev_resolution": resolution,
            "dev_mode": mode,
            "dev_type": dev_type,
        }
        return info

    def complete_report(self, report):
        if 'scantest' not in report:
            report['scantest'] = {}
        report['scantest'].update({
            'config': self.get_scanner_config()
        })

        imgpath = self.widget_tree.get_object("filechooserPicture").get_file()
        img = None
        if imgpath is not None:
            try:
                pil_img = PIL.Image.open(imgpath.get_path())
                pil_img.load()
                imgraw = io.BytesIO()
                pil_img.save(imgraw, format="PNG")
                imgraw.seek(0)
                imgraw = imgraw.read()
                img = base64.encodebytes(imgraw).decode("utf-8")
            except Exception as exc:
                logger.error("Failed to load image {}".format(
                    imgpath.get_path()), exc_info=exc
                )

        dev_type = self.widget_tree.get_object('liststoreScannerTypes')[
            self.widget_tree.get_object('comboboxScannerTypes').get_active()
        ][1]

        scanner = self.get_scanner()
        vendor = self.widget_tree.get_object("entryManufacturer").get_text()
        model = self.widget_tree.get_object("entryModel").get_text()
        nice_name = (
            scanner.nice_name
            if scanner is not None else
            "{} {}".format(vendor, model)
        )
        report['scanner'] = {
            'vendor': vendor,
            'model': model,
            'nicename': nice_name,
            'devid': scanner.name if scanner is not None else "unknown",
            'fullname': "{} {} ({})".format(vendor, model, nice_name),
            'type': str(dev_type),
        }
        if img is not None:
            logger.info("Image attached to report: {}".format(
                imgpath.get_uri())
            )
            report['scanner']['picture'] = img
        else:
            logger.info("No image attached to report")
        report['scanner']['options'] = self.options


class SysInfo(object):
    def __str__(self):
        return "System configuration"

    def get_info(self):
        try:
            uname = os.uname()
        except Exception as exc:
            logger.warning("Failed to get uname", exc_info=exc)
            uname = "unknown"
        return {
            'sys_arch': platform.architecture(),
            'sys_cpu_freq': int(psutil.cpu_freq().max),
            'sys_machine': platform.machine(),
            'sys_mem': int(psutil.virtual_memory().total),
            'sys_nb_cpus': multiprocessing.cpu_count(),
            'sys_os_uname': uname,
            'sys_platform_detailed': platform.platform(),
            'sys_platform_short': sys.platform,
            'sys_platform_uname': platform.uname(),
            'sys_proc': platform.processor(),
            'sys_python': sys.version,
            'sys_release': platform.release(),
            'sys_swap': int(psutil.swap_memory().total),
            'sys_system': platform.system(),
            'sys_type': os.name,
        }

    def get_user_info(self):
        return {
            "sys": "- " + "\n- ".join(
                [
                    "{}: {}".format(k[4:], v)
                    for (k, v) in self.get_info().items()
                ]
            )
        }

    def complete_report(self, report):
        report['system'] = self.get_info()
        try:
            report['system']['versions'] = {
                'pillow': (
                    "unknown" if not hasattr(PIL, "__version__")
                    else PIL.__version__
                ),
                'scan_library': "pyinsane2 " + pyinsane2.__version__,
                'test_program': "ironscanner " + __version__,
            }
        except Exception as exc:
            logger.warning("Failed to get python module version: {}".format(
                str(exc)
            ), exc_info=exc)


class TestSummary(object):
    TEMPLATE = """
Summary of the test:
- Scanner: {dev_name}
- Type: {dev_type}
- Source: {dev_source}
- Resolutions: {dev_resolution}
- Mode: {dev_mode}

Personal information that will be attached to the report:
- Name: {user_name}
- Email: {user_email}

System informations that will be attached to the report:
{sys}
    """

    def __init__(self, widget_tree, settings, sources):
        self.widget_tree = widget_tree
        self.sources = sources
        self.settings = settings

        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageSummary"):
            return
        if self.settings.get_scanner_id() is None:
            # skip the test scan and the result questions
            assistant.set_current_page(assistant.get_current_page() + 4)
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


class ScanThread(threading.Thread):
    def __init__(self, scanner, settings, progress_cb, result_cb):
        super().__init__(name="Test scan thread")
        self.scanner = scanner
        self.settings = settings
        self.progress_cb = progress_cb
        self.result_cb = result_cb
        self.condition = threading.Condition()

    def _upd_progression(self, image, progression):
        with self.condition:
            self.progress_cb(image, progression)
            self.condition.notify_all()

    def upd_progression(self, image, progression):
        with self.condition:
            GLib.idle_add(self._upd_progression, image, progression)
            self.condition.wait()

    def run(self):
        try:
            logger.info("### SCAN TEST ###")
            for (k, v) in self.settings.items():
                logger.info("Configuring scanner: {} = {}".format(k, v))
                trace.trace(pyinsane2.set_scanner_opt, self.scanner, k, [v])
            logger.info("Maximizing scan area ...")
            trace.trace(pyinsane2.maximize_scan_area, self.scanner)

            logger.info("Starting scan session ...")
            try:
                # we set multiple = True, pyinsane will take care of switching
                # it back to False if required
                scan_session = trace.trace(self.scanner.scan, multiple=True)
                expected_size = scan_session.scan.expected_size
                logger.info("Expected image size: {}".format(expected_size))
                page_nb = 0
                while True:
                    logger.info("Scanning page {}".format(page_nb))
                    try:
                        while True:
                            trace.trace(scan_session.scan.read)
                            logger.info("Available lines: {}".format(
                                scan_session.scan.available_lines
                            ))
                            self.upd_progression(
                                scan_session.scan.get_image(),
                                scan_session.scan.available_lines[1] /
                                expected_size[1]
                            )
                    except EOFError:
                        logger.info("End of page. Available lines: {}".format(
                            scan_session.scan.available_lines
                        ))
                        page_nb += 1
                        self.upd_progression(scan_session.scan.get_image(),
                                             1.0)
            except StopIteration:
                logger.info("Got StopIteration")
            logger.info("Scanned {} images".format(len(scan_session.images)))
            logger.info("### SCAN TEST SUCCESSFUL ###")
        except Exception as exc:
            logger.info("### SCAN TEST FAILED ###", exc_info=exc)
            GLib.idle_add(self.result_cb)
            return
        GLib.idle_add(self.result_cb)


class ScanTest(object):
    def __init__(self, widget_tree, scanner_settings):
        self.widget_tree = widget_tree
        self.scanner_settings = scanner_settings
        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )
        self.log_handler = LogHandler(
            widget_tree.get_object("textbufferOnTheFly"),
            widget_tree.get_object("scrolledwindowOnTheFly"),
            log_level=logging.INFO,
        )
        self.last_img = None

    def __str__(self):
        return "Scan test result"

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageTestScan"):
            self.log_handler.disable()
            return
        self.log_handler.enable()
        scanner = self.scanner_settings.get_scanner()
        settings = self.scanner_settings.get_scanner_config()
        ScanThread(
            scanner, settings,
            self._on_scan_progression, self._on_scan_result
        ).start()

    def _on_scan_progression(self, image, progression):
        self.last_img = image
        pixbuf = util.image2pixbuf(image)
        img_widget = self.widget_tree.get_object("imageOnTheFly")
        (pw, ph) = (pixbuf.get_width(), pixbuf.get_height())
        rect = img_widget.get_allocation()
        ratio = max(pw / rect.width, pw / rect.height)
        pixbuf = pixbuf.scale_simple(int(pw / ratio), int(ph / ratio),
                                     GdkPixbuf.InterpType.BILINEAR)
        img_widget.set_from_pixbuf(pixbuf)
        self.widget_tree.get_object("progressbarTestProgress").set_fraction(
            progression
        )

    def _on_scan_result(self):
        self.widget_tree.get_object("mainform").set_page_complete(
            self.widget_tree.get_object("pageTestScan"),
            True
        )
        self.log_handler.validate()

    def complete_report(self, report):
        if 'scantest' not in report:
            report['scantest'] = {}

        image = "(none)"
        try:
            if self.last_img is not None:
                image = io.BytesIO()
                self.last_img.save(image, format="PNG")
                image.seek(0)
                image = image.read()
                image = base64.encodebytes(image).decode("utf-8")
        except Exception as exc:
            image = "(Exception: {})".format(str(exc))
        report['scantest']['image'] = image
        report['scantest']['successful'] = self.widget_tree.get_object(
            "radiobuttonScanSuccessful"
        ).get_active()


class UserComment(object):
    def __init__(self, widget_tree):
        self.widget_tree = widget_tree

    def __str__(self):
        return "User comment"

    def complete_report(self, report):
        if 'user' not in report:
            report['user'] = {}
        buf = self.widget_tree.get_object("textbufferUserComment")
        start = buf.get_iter_at_offset(0)
        end = buf.get_iter_at_offset(-1)
        report['user']['comment'] = buf.get_text(start, end, False)


class ReportSenderThread(threading.Thread):
    def __init__(self, report_authors, cb):
        super().__init__(name="ReportSender")
        self.cb = cb
        self.report_authors = report_authors

    def run(self):
        report = {}
        logger.info("Building report ...")
        for author in self.report_authors:
            logger.info("* {}".format(str(author)))
            try:
                author.complete_report(report)
            except Exception as exc:
                logger.warning(
                    "Failed to build report section '{}'".format(str(author)),
                    exc_info=exc
                )
        report = json.dumps(report)
        logger.info("Report ready: {} Kbytes to send".format(
            int(len(report.encode("utf-8")) / 1024)
        ))

        logger.info("Connecting to {}".format(TARGET_HOST))
        if TARGET_PROTOCOL == "http":
            connection = http.client.HTTPConnection(host=TARGET_HOST)
        else:
            connection = http.client.HTTPSConnection(
                host=TARGET_HOST, context=SSL_CONTEXT
            )
        logger.info("Posting report...")
        logger.info("Please wait, this may take a while...")
        connection.request("POST", url=TARGET_PATH, headers={
            "Content-type": "application/json",
            "Accept": "application/json",
            'User-Agent': USER_AGENT,
        }, body=report)
        reply = connection.getresponse()
        if reply.status != http.client.OK:
            logger.error("Error from server: {} - {}\n".format(
                reply.status, reply.reason, reply.read().decode("utf-8")
            ))
            return
        reply_msg = reply.read().decode('utf-8')
        logger.info("Reply from server: {} - {} - {}".format(
            reply.status, reply.reason, reply_msg
        ))
        reply_msg = json.loads(reply_msg)
        url = "{}://{}{}".format(
            TARGET_PROTOCOL, TARGET_HOST, reply_msg['url']
        )
        logger.info("Report posted - Thank you for your contribution :-)")
        GLib.idle_add(self.cb, url)


class ReportSender(object):
    def __init__(self, widget_tree, report_authors):
        self.widget_tree = widget_tree
        self.txt_buffer = widget_tree.get_object("textbufferSendingReport")
        widget_tree.get_object("mainform").connect(
            "prepare", self._on_assistant_page_prepare
        )
        self.report_authors = report_authors
        self.log_handler = LogHandler(
            widget_tree.get_object("textbufferSendingReport"),
            widget_tree.get_object("scrolledwindowSendingResults"),
            log_level=logging.INFO,
        )

    def _on_assistant_page_prepare(self, assistant, page):
        if page is not self.widget_tree.get_object("pageSendReport"):
            self.log_handler.disable()
            return
        self.log_handler.enable()
        self.txt_buffer.set_text("")
        self.txt = []
        ReportSenderThread(self.report_authors, self._on_report_sent).start()

    def _on_report_sent(self, report_url):
        self.widget_tree.get_object("mainform").set_page_complete(
            self.widget_tree.get_object("pageSendReport"),
            True
        )
        self.widget_tree.get_object("linkbuttonOpenReport").set_label(
            report_url
        )
        self.widget_tree.get_object("linkbuttonOpenReport").set_uri(report_url)
        self.log_handler.validate()


def run_pyinsane2_daemon():
    import pyinsane2.sane.daemon
    logger.info("Pyinsane2 daemon: %s", str(sys.argv))
    pyinsane2.sane.daemon.main_loop(sys.argv[3], sys.argv[4:6])


def main():
    g_log_tracker.init()

    if getattr(sys, 'frozen', False):
        pyinsane_daemon = os.getenv('PYINSANE_DAEMON', '1')
        pyinsane_daemon = False if int(pyinsane_daemon) > 0 else True
        if pyinsane_daemon:
            # WORKAROUND for the Pyinsane workaround ... (see Linux/Sane
            # implementation)
            run_pyinsane2_daemon()
            return

    logger.info("Initializing pyinsane2 ...")
    trace.trace(pyinsane2.init)
    logger.info("Pyinsane2 ready")

    try:
        main_loop = GLib.MainLoop()

        application = Gtk.Application()

        widget_tree = util.load_uifile("mainform.glade")

        Greeting(widget_tree)
        MainForm(application, main_loop, widget_tree)
        user_info = PersonalInfo(widget_tree)
        scan_settings = ScannerSettings(widget_tree)
        sys_info = SysInfo()
        TestSummary(widget_tree, scan_settings,
                    [user_info, scan_settings, sys_info])
        scan_test = ScanTest(widget_tree, scan_settings)
        user_comment = UserComment(widget_tree)

        ReportSender(widget_tree, [
            user_info, scan_settings, sys_info, scan_test, user_comment,
            g_log_tracker,
        ])

        application.register()

        main_loop.run()
        logger.info("Quitting")
    finally:
        logger.info("Exiting Pyinsane2")
        pyinsane2.exit()
    logger.info("Good bye")


if __name__ == "__main__":
    main()
