"""
Various utility functions
"""

import logging
import os
import sys

import pkg_resources

from gi.repository import GdkPixbuf
from gi.repository import Gtk


logger = logging.getLogger(__name__)


def _get_resource_path(filename, pkg="ironscanner"):
    """
    Gets the absolute location of a datafile packaged.
    This function throws if the file is not found, but the error depends on the
    way the package was installed.

    Arguments:
        filename -- the relative filename of the file to load.

    Returns:
        the full path of the file.

    Throws:
        Exception -- if the file is not found.
    """
    if getattr(sys, 'frozen', False):
        path = os.path.join(sys._MEIPASS, "data", filename)
        if os.path.exists(path):
            return path

    path = pkg_resources.resource_filename(pkg, filename)

    if not os.access(path, os.R_OK):
        raise FileNotFoundError(  # NOQA (Python 3.x only)
            "Can't find resource file '%s'. Aborting" % filename
        )

    logger.debug("For filename '%s' got file '%s'", filename, path)
    return path


def load_pixbuf(filename):
    img_file = _get_resource_path(filename)
    return GdkPixbuf.Pixbuf.new_from_file(img_file)


def load_uifile(filename):
    """
    Load a .glade file and return the corresponding widget tree

    Arguments:
        filename -- glade filename to load.

    Returns:
        GTK Widget tree

    Throws:
        Exception -- If the file cannot be found
    """
    widget_tree = Gtk.Builder()
    ui_file = _get_resource_path(filename)
    widget_tree.add_from_file(ui_file)
    return widget_tree
