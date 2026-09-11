"""
Placeholder reader implementation.
"""

from hardware.base.reader_base import ReaderBase


class PlaceholderReader(ReaderBase):

    @property
    def name(self):
        return "Placeholder Reader"

    def connect(self):
        return True

    def disconnect(self):
        pass

    def health_check(self):
        return True

    def read_card(self):
        return None