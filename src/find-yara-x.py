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

import logging
import os
import string
import typing
from dataclasses import dataclass
from enum import Enum
from PySide6 import QtCore, QtWidgets, QtGui
import idaapi
import yara_x
from highlighting_chooser import HighlightingChoose

logger = logging.getLogger("FindYaraX")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.handlers[0].setFormatter(
    logging.Formatter("[%(name)s] %(levelname)s: %(message)s")
)


__author__ = "@herrcore, @_p0ly_, @milankovo"

PLUGIN_NAME = "FindYaraX"
PLUGIN_HOTKEY = "Ctrl-Alt-Y"
VERSION = "4.2.0"


class PreviousFilenames:
    REG_KEY = "FindYaraX"
    MAX_RECS = 20

    @staticmethod
    def read():
        return idaapi.reg_read_strlist(PreviousFilenames.REG_KEY)

    @staticmethod
    def add_filename(filename):
        idaapi.reg_update_filestrlist(
            PreviousFilenames.REG_KEY, filename, maxrecs=PreviousFilenames.MAX_RECS
        )

    @staticmethod
    def remove_filename(filename):
        idaapi.reg_update_filestrlist(
            PreviousFilenames.REG_KEY,
            None,
            maxrecs=PreviousFilenames.MAX_RECS,
            rem=filename,
        )


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
    match_length: int

    COLUMNS: typing.ClassVar[list] = [
        ["Address", idaapi.Choose.CHCOL_EA | 10],
        ["Rule Name", idaapi.Choose.CHCOL_PLAIN | 20],
        ["Match Name", idaapi.Choose.CHCOL_PLAIN | 20],
        ["Match", idaapi.Choose.CHCOL_PLAIN | 40],
        ["Type", idaapi.Choose.CHCOL_PLAIN | 10],
        ["Length", idaapi.Choose.CHCOL_PLAIN | 10],
    ]

    def __iter__(self):
        return iter(
            [
                idaapi.ea2str(self.address),
                self.rule_name,
                self.match_name,
                self.match,
                self.match_type.value,
                str(self.match_length),
            ]
        )


class YaraSearchResultChooser(HighlightingChoose):
    def __init__(
        self,
        title,
        items: list[result_t],
        flags=idaapi.CH_MULTI,
    ):
        super().__init__(title=title, cols=result_t.COLUMNS, flags=flags)
        self.items: list[result_t] = items

    def OnGetLine(self, n):
        return [*self.items[n]]

    def OnGetEA(self, n: int) -> int:
        return self.items[n].address

    def OnGetLength(self, n: int) -> int:
        return self.items[n].match_length

    def OnGetSize(self):
        return len(self.items)


def handle_dropped_file(file_path: str) -> bool:
    if not os.path.isfile(file_path):
        logger.debug(f"Dropped file is not a file: {file_path}")
        return False

    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".yara", ".yar", ".rules"]:
        PreviousFilenames.add_filename(file_path)
        search(file_path)
        return True

    return False


class FileDropFilter(QtCore.QObject):
    def on_drop(self, obj, event) -> bool:
        logger.debug(f"Drop on {obj} {event.mimeData().urls()}")

        if not event.mimeData().hasUrls():
            return False
        handled = False
        for url in event.mimeData().urls():
            logger.debug(f"Dropped file: {url.toLocalFile()}")
            handled |= handle_dropped_file(url.toLocalFile())
        return handled

    def eventFilter(self, obj, event):
        match event.type():
            case QtCore.QEvent.Type.Drop:
                if self.on_drop(obj, event):
                    event.acceptProposedAction()
                    return True
            case _:
                pass

        return super().eventFilter(obj, event)


class RecentYaraFilesChooser(idaapi.Choose):
    def __init__(self, title: str, *args, **kwargs):
        super().__init__(
            *args,
            title=title,
            cols=[["Filename", idaapi.Choose.CHCOL_PATH | 40]],
            **kwargs,
        )
        self.items = PreviousFilenames.read()

    def OnGetLine(self, n):
        return [self.items[n]]

    def OnSelectLine(self, sel: int):
        search(self.items[sel])

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, sel: int):
        self.items = PreviousFilenames.read()
        if len(self.items) == 0:
            return [idaapi.Choose.EMPTY_CHOOSER, idaapi.Choose.NO_SELECTION]
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

    def OnDeleteLine(self, sel: int):
        PreviousFilenames.remove_filename(self.items[sel])
        self.items = PreviousFilenames.read()
        if len(self.items) == 0:
            return [idaapi.Choose.ALL_CHANGED, idaapi.Choose.NO_SELECTION]
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(sel)


def search(yara_file: str):
    logger.info(f"Searching for Yara rules in {yara_file}")
    if os.path.exists(yara_file) is False:
        logger.error(f"The file {yara_file} does not exist")
        return

    try:
        rules_text = open(yara_file, "r", encoding="utf-8").read()
        rules = yara_x.compile(rules_text)
    except yara_x.CompileError as e:
        idaapi.warning(f"Cannot compile Yara rules\n\n{e}")
        return
    except Exception as e:
        logger.error(f"Cannot open Yara rules from {yara_file}", exc_info=e)
        return

    logger.debug("Gathering segments...")
    memory = mapped_data()
    logger.debug("Searching for Yara matches...")

    items: list[result_t] = yarasearch(memory, rules)
    if not items:
        logger.info("No matches found")
        return
    logger.debug("Displaying results...")
    c = YaraSearchResultChooser(title="FindYara scan results", items=items)
    c.Show()


def process_yara_match(m: yara_x.Match, memory: mapped_data):
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


def yarasearch(memory: mapped_data, rules: yara_x.Rules):
    values: list[result_t] = list()
    matches: yara_x.ScanResults = rules.scan(data=memory.data)
    for rule_match in matches.matching_rules:
        for pattern in rule_match.patterns:
            values.extend(
                [
                    result_t(
                        memory.offset_to_virtual_address(match.offset),
                        rule_match.identifier,
                        pattern.identifier,
                        *process_yara_match(match, memory),
                        match.length,
                    )
                    for match in pattern.matches
                ]
            )
    return values


class search_ah_t(idaapi.action_handler_t):
    def activate(self, ctx: idaapi.action_ctx_base_t):
        yara_file = idaapi.ask_file(
            False, "*.yara;*.yar;*.rules", "Choose a yara file..."
        )
        if yara_file is None:
            logger.error("You must choose a yara file to scan with")
            return
        if not os.path.isfile(yara_file):
            logger.error(f"{yara_file} is not a file")
            return

        PreviousFilenames.add_filename(yara_file)
        search(yara_file)

    def update(self, ctx: idaapi.action_ctx_base_t):
        return idaapi.AST_ENABLE_ALWAYS


class open_recent_files_ah_t(idaapi.action_handler_t):
    def activate(self, ctx: idaapi.action_ctx_base_t):
        c = RecentYaraFilesChooser("Recent Yara files")
        c.Show()
        return

    def update(self, ctx: idaapi.action_ctx_base_t):
        return idaapi.AST_ENABLE_ALWAYS


def get_main_window():
    windows = QtWidgets.QApplication.allWindows()
    for w in windows:
        if (
            isinstance(w, QtGui.QWindow)
            and w.objectName() == "IDAMainWindowClassWindow"
        ):
            return w

    return None


# --------------------------------------------------------------------------
# Plugin
# --------------------------------------------------------------------------
class FindYaraX_Plugin_t(idaapi.plugin_t):
    comment = "FindYaraX plugin for IDA Pro (using yara_x framework)"
    help = ""
    wanted_name = PLUGIN_NAME
    flags = idaapi.PLUGIN_HIDE
    search_action_name = "FindYaraX:Search"
    recent_action_name = "FindYaraX:Recent"

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milankovo.findyarax"
        addon.name = "FindYara"
        addon.producer = "@milankovo, @herrcore, @_p0ly_"
        addon.url = "https://github.com/milankovo/ida-yara-x"
        addon.version = VERSION
        idaapi.register_addon(addon)

        self.register_actions()
        self.install_drop_filter()

        return idaapi.PLUGIN_KEEP

    def register_actions(self):
        search_bytes_action = idaapi.action_desc_t(
            self.search_action_name,
            "Yara-x rules",
            search_ah_t(),
            PLUGIN_HOTKEY,
        )
        idaapi.register_action(search_bytes_action)

        recent_action = idaapi.action_desc_t(
            self.recent_action_name, "Recent yara-x files", open_recent_files_ah_t()
        )
        idaapi.register_action(recent_action)
        idaapi.attach_action_to_menu(
            "Search/next sequence of bytes", self.search_action_name, idaapi.SETMENU_APP
        )
        idaapi.attach_action_to_menu(
            "View/Recent scripts", self.recent_action_name, idaapi.SETMENU_APP
        )

    def install_drop_filter(self):
        main_window = get_main_window()
        if main_window:
            self.filter = FileDropFilter()
            main_window.installEventFilter(self.filter)
        else:
            self.filter = None

    def term(self):
        self.remove_drop_filter()
        self.unregister_actions()
        pass

    def unregister_actions(self):
        idaapi.unregister_action(self.search_action_name)
        idaapi.unregister_action(self.recent_action_name)

    def remove_drop_filter(self):
        if self.filter is None:
            return

        main_window = get_main_window()
        if main_window:
            main_window.removeEventFilter(self.filter)
            del self.filter
            self.filter = None

    def run(self, arg): ...


def PLUGIN_ENTRY():
    return FindYaraX_Plugin_t()
