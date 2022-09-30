"""
Add a new mitmproxy option.

Usage:

    mitmproxy -s options-simple.py --set addheader true
"""
from mitmproxy import ctx


class AddHeader:
    def __init__(self):
        self.num = 0

    def load(self, loader):
        loader.add_option(
            name="ignore-conn-depth",
            typespec=int,
            default=0,
            help="Add a count header to responses",
        )

addons = [AddHeader()]