class DummyOption(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.title = name
        self.desc = name
        self.val_type = "meh"
        self.unit = "meh"
        self.size = 0
        self.capabilities = "meh"
        self.constraint_type = "meh"
        self.constraint = []


class DummyScanner(object):
    def __init__(self):
        self.name = "No scanner found"
        self.nice_name = "No scanner found"
        self.model = "No scanner found"
        self.vendor = ""

        self.options = {
            "source": DummyOption("source", "None"),
            "resolution": DummyOption("resolution", 0),
            "mode": DummyOption("mode", "None"),
        }
