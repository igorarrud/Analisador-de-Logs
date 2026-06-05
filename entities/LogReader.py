class LogReader:
    def __init__(self, path, mode='r'):
        self.path = path
        self.mode = mode

    def open_archive(self):
        with open(self.path, self.mode) as file:
            for line in file:
                yield line.strip()