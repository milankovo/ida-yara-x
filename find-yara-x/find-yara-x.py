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

import idaapi
import yara_x
from PySide6 import QtWidgets

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
VERSION = "4.0.0"


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


class YaraSearchResultChooser(idaapi.Choose):
    def __init__(
        self,
        title,
        items: list[result_t],
        flags=idaapi.CH_MULTI,
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
        ranges = idaapi.rangeset_t()
        for item in items:
            ranges.add(item.address, item.address + item.match_length)
            break
        self.hooks = YaraSearchUIHooks(self, ranges)
        self.hooks.hook()

        all_ranges = idaapi.rangeset_t()
        for item in items:
            all_ranges.add(item.address, item.address + item.match_length)
        self.view_hooks = YaraSearchViewHooks(self, all_ranges, items)
        self.view_hooks.hook()

    def OnGetLine(self, n):
        return [*self.items[n]]

    def OnGetEA(self, n):
        return self.items[n].address

    def OnGetSize(self):
        return len(self.items)

    def OnClose(self):
        self.hooks.unhook()
        self.view_hooks.unhook()

    def OnSelectionChange(self, sel: list[int]):
        self.hooks.clear_highlight()
        for s in sel:
            selected_item: result_t = self.items[s]
            self.hooks.add_highlight(selected_item.address, selected_item.match_length)

        idaapi.refresh_idaview_anyway()
        if len(sel) == 1:
            idaapi.jumpto(
                selected_item.address, -1, idaapi.UIJMP_DONTPUSH | idaapi.UIJMP_ANYVIEW
            )


class YaraSearchViewHooks(idaapi.View_Hooks):
    def __init__(
        self,
        chooser: YaraSearchResultChooser,
        ranges: idaapi.rangeset_t,
        items: list[result_t],
    ):
        super().__init__()
        self.chooser = chooser
        self.ranges = ranges
        self.items = items

    def view_loc_changed(
        self,
        view: "idaapi.TWidget",
        now: "idaapi.lochist_entry_t",
        was: "idaapi.lochist_entry_t",
    ) -> None:
        """The location for the view has changed (can be either the place_t, the renderer_info_t, or both.)

        :param view: (TWidget *)
        :param now: (const lochist_entry_t *)
        :param was: (const lochist_entry_t *)"""

        place: idaapi.place_t = now.place()
        if not place:
            return
        ea = place.toea()
        if ea == idaapi.BADADDR:
            return

        # logger.debug(f"View location changed: {place} {ea:08x}")
        range = place_to_range(place)
        if not range:
            return
        range.intersect(self.ranges)
        if not range:
            return
        ea = range.next_addr(0)
        if ea == idaapi.BADADDR:
            return
        for idx, item in enumerate(self.items):
            if item.address == ea:
                twidget = self.chooser.GetWidget
                widget: QtWidgets.QWidget = idaapi.PluginForm.TWidgetToQtPythonWidget(
                    twidget
                )  # type: ignore
                table_view: QtWidgets.QTableView = widget.findChild(
                    QtWidgets.QTableView
                )  # type: ignore

                if table_view is not None:
                    if len(table_view.selectedIndexes()) == 1:
                        table_view.selectRow(idx)
                break


def place_to_range(place: idaapi.place_t) -> idaapi.rangeset_t:
    nm = place.name()
    ea = place.toea()
    if ea == idaapi.BADADDR:
        return idaapi.rangeset_t()
    # logger.debug(f"Rendering line at {ea:08x} of type {nm}")

    range = idaapi.rangeset_t()

    match nm:
        case "hexplace_t":
            range.add(ea, ea + 16)
        case "idaplace_t":  # handled by _
            range.add(ea, ea + idaapi.get_item_size(ea))
        case "hexrays_place_t":
            # does not work as expected
            ...
        case "mbui_place_t":
            # TODO
            ...
        case _:
            logger.debug(f"Unknown place type {nm} ")
            range.add(ea, ea + idaapi.get_item_size(ea))

    return range


class YaraSearchUIHooks(idaapi.UI_Hooks):
    def __init__(self, chooser, ranges: idaapi.rangeset_t):
        super().__init__()
        self.chooser = chooser
        self.ranges = ranges

    def get_lines_rendering_info(
        self, out, widget, rin: idaapi.lines_rendering_input_t
    ):
        """
        Highlight the selected item in other views.
                           ///< cb: get lines rendering information
                          ///< \param out (lines_rendering_output_t *)
                          ///< \param widget (const TWidget *)
                          ///< \param info (const lines_rendering_input_t *)
                          ///< \return void
        """

        for section_lines in rin.sections_lines:
            line: idaapi.twinline_t
            for line in section_lines:
                range = place_to_range(line.at)

                range.intersect(self.ranges)

                ra: idaapi.range_t
                for ra in range.as_rangevec():
                    e = idaapi.line_rendering_output_entry_t(line)
                    e.bg_color = idaapi.CK_EXTRA1

                    # logger.debug(
                    #     f"Highlighting from {ra.start_ea:08x} to {ra.end_ea:08x}"
                    # )

                    if line.at.name() == "hexplace_t":
                        rel_idx = ra.start_ea - line.at.toea()
                        e.cpx = 18 + 3 * (rel_idx) + (rel_idx > 7)
                        e.nchars = ra.size() * 3 - 1
                        e.flags = idaapi.LROEF_CPS_RANGE
                        out.entries.push_back(e)
                    else:
                        out.entries.push_back(e)

    def clear_highlight(self):
        self.ranges.clear()

    def add_highlight(self, ea, size):
        self.ranges.add(ea, ea + size)

    def update_highlight(self, ea, size):
        self.ranges.clear()
        self.add_highlight(ea, size)


class RecentYaraFilesChooser(idaapi.Choose):
    def __init__(
        self,
        title,
        flags=0,
        width=None,
        height=None,
        embedded=False,
    ):
        super().__init__(
            title=title,
            cols=[["Filename", idaapi.Choose.CHCOL_PATH | 40]],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded,
        )
        self.items = PreviousFilenames.read()

    def OnGetLine(self, n):
        return [self.items[n]]

    def OnSelectLine(self, sel):
        search(self.items[sel])

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, sel):
        self.items = PreviousFilenames.read()
        return [idaapi.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

    def OnDeleteLine(self, sel):
        PreviousFilenames.remove_filename(self.items[sel])
        self.items = PreviousFilenames.read()
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

    values = yarasearch(memory, rules)
    if not values:
        logger.info("No matches found")
        return
    logger.debug("Displaying results...")
    c = YaraSearchResultChooser("FindYara scan results", values)
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
    matches = rules.scan(data=memory.data)
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

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.search_action_name)
        idaapi.unregister_action(self.recent_action_name)
        pass

    def run(self, arg): ...


def PLUGIN_ENTRY():
    return FindYaraX_Plugin_t()
