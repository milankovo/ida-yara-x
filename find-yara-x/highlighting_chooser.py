import idaapi
import abc
import logging
from PySide6 import QtWidgets

logger = logging.getLogger()


def place_to_rangeset(place: idaapi.place_t) -> idaapi.rangeset_t:
    nm = place.name()
    ea = place.toea()
    if ea == idaapi.BADADDR:
        return idaapi.rangeset_t()

    range = idaapi.rangeset_t()

    match nm:
        case "hexplace_t":
            range.add(ea, ea + 16)
        case "idaplace_t":
            range.add(ea, ea + idaapi.get_item_size(ea))
        case _:
            range.add(ea, ea + idaapi.get_item_size(ea))

    return range


class HighlightingChooseViewHooks(idaapi.View_Hooks):
    def __init__(self, chooser: "HighlightingChoose"):
        super().__init__()
        self.chooser = chooser
        self.all_ranges: idaapi.rangeset_t | None = None

    def build_all_ranges(self):
        if self.all_ranges is not None:
            return
        self.all_ranges = idaapi.rangeset_t()
        for idx in range(0, self.chooser.OnGetSize()):
            ea = self.chooser.OnGetEA(idx)
            size = self.chooser.OnGetLength(idx)
            self.all_ranges.add(ea, ea + size)
            logger.debug(f"Added range {ea:08x} - {ea + size:08x}")

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

        logger.debug(f"View location changed: {view} {now} {was}")

        if self.chooser.last_selection_len > 1:
            return

        place: idaapi.place_t = now.place()
        if not place:
            return
        ea = place.toea()
        if ea == idaapi.BADADDR:
            return

        rangeset = place_to_rangeset(place)
        if not rangeset:
            return

        if self.all_ranges is None:
            self.build_all_ranges()

        if self.all_ranges is None:
            return

        rangeset.intersect(self.all_ranges)
        if not rangeset:
            return
        ea = rangeset.next_addr(0)
        if ea == idaapi.BADADDR:
            return

        for idx in range(0, self.chooser.OnGetSize()):
            item_ea = self.chooser.OnGetEA(idx)
            if item_ea != ea:
                continue

            widget: QtWidgets.QWidget = idaapi.PluginForm.TWidgetToQtPythonWidget(
                self.chooser.GetWidget()
            )  # type: ignore

            table_view: QtWidgets.QTableView = widget.findChild(QtWidgets.QTableView)  # type: ignore

            table_view.selectRow(idx)
            break


class HighlightingChoose(idaapi.Choose):
    def __init__(self, flags=0, *args, **kwargs):
        super().__init__(*args, flags=flags, **kwargs)
        self.ui_hooks = HighlightingChooseUIHooks(self)
        self.ui_hooks.hook()
        self.view_hooks = HighlightingChooseViewHooks(self)
        self.view_hooks.hook()
        self.last_selection_len: int = 0

    def clear_highlight(self):
        self.ui_hooks.clear_highlight()

    def add_highlight(self, ea, size):
        self.ui_hooks.add_highlight(ea, size)

    def update_highlight(self, ea, size):
        self.ui_hooks.update_highlight(ea, size)

    def unhook(self):
        self.ui_hooks.unhook()
        self.view_hooks.unhook()

    def OnClose(self):
        self.unhook()
        return super().OnClose()

    def OnSelectionChange(self, sel: list[int] | int):
        self.clear_highlight()

        if isinstance(sel, int):
            sel = [sel]

        for n in sel:
            self.add_highlight(self.OnGetEA(n), self.OnGetLength(n))

        idaapi.refresh_idaview_anyway()
        self.last_selection_len = len(sel)

        if self.last_selection_len != 1:
            return
        idaapi.jumpto(
            self.OnGetEA(sel[0]), -1, idaapi.UIJMP_DONTPUSH | idaapi.UIJMP_ANYVIEW
        )

    @abc.abstractmethod
    def OnGetLength(self, n: int) -> int:
        pass


class HighlightingChooseUIHooks(idaapi.UI_Hooks):
    def __init__(self, chooser: HighlightingChoose):
        super().__init__()
        self.chooser: HighlightingChoose = chooser
        self.highlight_ranges: idaapi.rangeset_t = idaapi.rangeset_t()
        self.hex_prefix_length: int = self.guess_hexplace_prefix_length()

    def guess_hexplace_prefix_length(self) -> int:
        if idaapi.inf_is_64bit():
            return 16 + 2
        if idaapi.inf_is_32bit_exactly():
            return 8 + 2
        if idaapi.inf_is_16bit():
            return 4 + 2
        return 8 + 2

    def get_lines_rendering_info(
        self, out, widget, rin: idaapi.lines_rendering_input_t
    ):
        for section_lines in rin.sections_lines:
            line: idaapi.twinline_t
            for line in section_lines:
                rangeset: idaapi.rangeset_t = place_to_rangeset(line.at)
                rangeset.intersect(self.highlight_ranges)
                ra: idaapi.range_t
                for ra in rangeset:
                    e = idaapi.line_rendering_output_entry_t(line)
                    e.bg_color = idaapi.CK_EXTRA1

                    match line.at.name():
                        case "hexplace_t":
                            rel_idx: int = ra.start_ea - line.at.toea()
                            e.cpx = self.hex_prefix_length + 3 * (rel_idx) + (rel_idx > 7)
                            e.nchars = ra.size() * 3 - 1
                            e.flags = idaapi.LROEF_CPS_RANGE
                            out.entries.push_back(e)
                        case _:
                            out.entries.push_back(e)

    def clear_highlight(self):
        self.highlight_ranges.clear()

    def add_highlight(self, ea, size):
        self.highlight_ranges.add(ea, ea + size)

    def update_highlight(self, ea, size):
        self.highlight_ranges.clear()
        self.add_highlight(ea, size)
