"""
Various utility functions
"""

import io
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
        path = os.path.join(sys._MEIPASS, "data", os.path.basename(filename))
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


def load_text(filename):
    with open(_get_resource_path(filename), 'r') as file_descriptor:
        return file_descriptor.read().strip()


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


def image2pixbuf(img):
    """
    Convert an image object to a gdk pixbuf
    """
    if img is None:
        return None
    file_desc = io.BytesIO()
    try:
        img.save(file_desc, "ppm")
        contents = file_desc.getvalue()
    finally:
        file_desc.close()
    loader = GdkPixbuf.PixbufLoader.new_with_type("pnm")
    try:
        loader.write(contents)
        pixbuf = loader.get_pixbuf()
    finally:
        loader.close()
    return pixbuf
