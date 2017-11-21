from gi.repository import GLib

from . import util


def main():
    main_loop = GLib.MainLoop()

    widget_tree = util.load_uifile("mainform.glade")
    mainform = widget_tree.get_object("mainform")
    mainform.connect("close", lambda w: main_loop.quit())
    mainform.connect("escape", lambda w: main_loop.quit())
    mainform.connect("cancel", lambda w: main_loop.quit())
    mainform.show_all()

    main_loop.run()


if __name__ == "__main__":
    main()
