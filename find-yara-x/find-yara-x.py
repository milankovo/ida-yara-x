########################################################################################
##
## All credit to David Berard (@_p0ly_) https://github.com/polymorf/findcrypt-yara
##
## This plugin is simply a copy of his excellent findcrypt-yara plugin only expanded
## use allow searching for any yara rules.
##
## ______ _____ _   _______  __   _____  ______  ___       __   __
## |  ___|_   _| \ | |  _  \ \ \ / / _ \ | ___ \/ _ \      \ \ / /
## | |_    | | |  \| | | | |  \ V / /_\ \| |_/ / /_\ \______\ V /
## |  _|   | | | . ` | | | |   \ /|  _  ||    /|  _  |______/   \
## | |    _| |_| |\  | |/ /    | || | | || |\ \| | | |     / /^\ \
## \_|    \___/\_| \_/___/     \_/\_| |_/\_| \_\_| |_/     \/   \/
##
##
## IDA plugin for Yara scanning... find those Yara matches!
##
## Updated for IDA 9.xx and Python 3
## Updated for yara-x (pip install yara-x)
##
## To install:
##      Copy script into plugins directory:
##        - C:\Program Files\<ida version>\plugins,
##        - `idaapi.get_ida_subdirs("plugins")`
##
## To run:
##      Ctl+Alt+Y or Edit->Plugins->FindYaraX
##      Use the dialogue box to select your yara rule file and start scanning!
##
########################################################################################

import idaapi
import yara_x
import string
import logging
from dataclasses import dataclass
from enum import Enum
import typing

logger = logging.getLogger("FindYaraX")
logger.setLevel(logging.WARNING)
formatter = logging.Formatter("[%(name)s] %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)


__author__ = "@herrcore, @_p0ly_, @milankovo"

PLUGIN_NAME = "FindYaraX"
PLUGIN_HOTKEY = "Ctrl-Alt-Y"
VERSION = "4.0.0"


class MatchType(Enum):
    ASCII_STRING = "ascii string"
    WIDE_STRING = "wide string"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass
class segment:
    va: int
    offset_start: int
    offset_end: int


def segments():
    seg: idaapi.segment_t = idaapi.get_first_seg()
    while seg is not None:
        yield seg
        seg = idaapi.get_next_seg(seg.start_ea)


class mapped_data:
    def __init__(self):
        self.segments = []
        self.data = bytes()

        for seg in segments():
            self.add_segment(seg)

    def add_segment(self, seg: idaapi.segment_t):
        chunk = idaapi.get_bytes(seg.start_ea, seg.size())
        sz = len(self.data)

        self.segments.append(segment(seg.start_ea, sz, sz + len(chunk)))
        self.data += chunk

    def offset_to_virtual_address(self, offset):
        for seg in self.segments:
            if seg.offset_start <= offset < seg.offset_end:
                return seg.va + (offset - seg.offset_start)

        return idaapi.BADADDR

    def __getitem__(self, *args):
        return self.data.__getitem__(*args)


@dataclass
class result_t:
    address: int
    rule_name: str
    match_name: str
    match: str
    match_type: MatchType

    COLUMNS: typing.ClassVar[list] = [
        ["Address", idaapi.Choose.CHCOL_EA | 10],
        ["Rule Name", idaapi.Choose.CHCOL_PLAIN | 20],
        ["Match Name", idaapi.Choose.CHCOL_PLAIN | 20],
        ["Match", idaapi.Choose.CHCOL_PLAIN | 40],
        ["Type", idaapi.Choose.CHCOL_PLAIN | 10],
    ]

    def __iter__(self):
        return iter(
            [
                idaapi.ea2str(self.address),
                self.rule_name,
                self.match_name,
                self.match,
                self.match_type.value,
            ]
        )


class YaraSearchResultChooser(idaapi.Choose):
    def __init__(
        self,
        title,
        items,
        flags=0,
        width=None,
        height=None,
        embedded=False,
    ):
        super().__init__(
            title=title,
            cols=result_t.COLUMNS,
            flags=flags,
            width=width,
            height=height,
            embedded=embedded,
        )
        self.items = items

    def OnClose(self):
        return

    def OnGetLine(self, n):
        return [*self.items[n]]

    def OnGetEA(self, n):
        return self.items[n].address

    def OnGetSize(self):
        return len(self.items)


# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------
class FindYaraX_Plugin_t(idaapi.plugin_t):
    comment = "FindYaraX plugin for IDA Pro (using yara_x framework)"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    flags = 0

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milankovo.findyarax"
        addon.name = "FindYara"
        addon.producer = "@milankovo, @herrcore, @_p0ly_"
        addon.url = "https://github.com/milankovo/ida-yara-x"
        addon.version = VERSION
        idaapi.register_addon(addon)
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def search(self, yara_file):
        try:
            rules_text = open(yara_file, "r", encoding="utf-8").read()
            rules = yara_x.compile(rules_text)
        except yara_x.CompileError as e:
            logger.error(f"Cannot compile Yara rules from {yara_file}\n\n{e}")
            return
        except Exception as e:
            logger.error(f"Cannot open Yara rules from {yara_file}", exc_info=e)
            return

        logger.debug("[FindYaraX] Gathering segments...")
        memory = mapped_data()
        logger.debug("[FindYaraX] Searching for Yara matches...")

        values = self.yarasearch(memory, rules)
        if not values:
            logger.error("[FindYaraX] No matches found")
            return
        logger.debug("[FindYaraX] Displaying results...")
        c = YaraSearchResultChooser("FindYara scan results", values)
        c.Show()

    def process_yara_match(self, m: yara_x.Match, memory: mapped_data):
        matched_bytes = bytearray(memory[m.offset : m.offset + m.length])

        if m.xor_key is not None and m.xor_key != 0:
            matched_bytes = bytearray([c ^ m.xor_key for c in matched_bytes])

        def test(allowed_chars):
            return all(chr(c) in allowed_chars for c in matched_bytes)

        if test(string.printable):
            return matched_bytes.decode("utf-8"), MatchType.ASCII_STRING

        if test(string.printable + "\x00") and b"\x00\x00" not in matched_bytes:
            return matched_bytes.decode("utf-16"), MatchType.WIDE_STRING

        return matched_bytes.hex(" "), MatchType.BINARY

    def yarasearch(self, memory: mapped_data, rules: yara_x.Rules):
        values = list()
        matches = rules.scan(data=memory.data)
        for rule_match in matches.matching_rules:
            for pattern in rule_match.patterns:
                values.extend(
                    [
                        result_t(
                            memory.offset_to_virtual_address(match.offset),
                            rule_match.identifier,
                            pattern.identifier,
                            *self.process_yara_match(match, memory),
                        )
                        for match in pattern.matches
                    ]
                )
        return values

    def run(self, arg):
        yara_file = idaapi.ask_file(0, "*.yara;*.yar;*.rules", "Choose a yara file...")
        if yara_file is None:
            logger.error("You must choose a yara file to scan with")
            return

        self.search(yara_file)


def PLUGIN_ENTRY():
    return FindYaraX_Plugin_t()
