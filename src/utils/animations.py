import threading
import sys
import os
from alive_progress import alive_bar
import time

class Spinner(threading.Thread):
    def __init__(self):
        super(Spinner, self).__init__()
        self._stop = False
        self.chars = ["▏", "▎", "▍", "▌", "▋", "▊", "▉", "█", "▉", "▊", "▌", "▍", "▎"]

    def run(self):
        with alive_bar(manual=True) as bar:
            counter = 0
            while not self._stop:
                sys.stdout.flush()
                time.sleep(.25)
                counter += .05
                if counter< 96:
                    bar(counter)

    def cursor_visible(self):
        os.system("tput cvvis")

    def cursor_invisible(self):
        os.system("tput civis")

    def stop(self):
        self._stop = True

    def stopped(self):
        return self._stop