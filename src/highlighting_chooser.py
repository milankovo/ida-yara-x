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
    def __init__(self, chooser: "HighlightingChoose", enabled: bool = True):
        super().__init__()
        self.chooser = chooser
        self.all_ranges: idaapi.rangeset_t | None = None
        self.enabled: bool = enabled

    def build_all_ranges(self):
        if self.all_ranges is not None:
            return
        self.all_ranges = idaapi.rangeset_t()
        for idx in range(0, self.chooser.OnGetSize()):
            ea = self.chooser.OnGetEA(idx)
            size = self.chooser.OnGetLength(idx)
            self.all_ranges.add(ea, ea + size)
            # logger.debug(f"Added range {ea:08x} - {ea + size:08x}")

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

        if not self.enabled:
            return

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
        self.view_hooks = HighlightingChooseViewHooks(self, enabled=False)
        self.view_hooks.hook()
        self.last_selection_len: int = 0
        self.highlight_all_matches: bool = False
        self.highlight_all_action_name = f"highlight_all_matches_{id(self)}"
        self.synchronization_action_name = f"enable_view_hooks_{id(self)}"

        # Register the action
        self.register_highlight_action()
        self.register_enable_view_hooks_action()

    def register_highlight_action(self):
        action_handler = HighlightAllMatchesHandler(self)
        action_desc = idaapi.action_desc_t(
            name=self.highlight_all_action_name,
            label="Highlight All Matches",
            handler=action_handler,
            shortcut="Ctrl-Shift-H",  # Shortcut
            tooltip="Toggle highlighting of all matches",  # Tooltip
        )
        ok = idaapi.register_action(desc=action_desc)
        idaapi.update_action_checkable(self.highlight_all_action_name, True)
        idaapi.update_action_checked(
            self.highlight_all_action_name, self.highlight_all_matches
        )
        assert ok, f"Failed to register action {self.highlight_all_action_name}"

    def register_enable_view_hooks_action(self):
        action_handler = EnableViewHooksHandler(self.view_hooks)
        action_desc = idaapi.action_desc_t(
            self.synchronization_action_name,  # Name
            "Sync selection with current location in other views",  # Label
            action_handler,  # Handler
            "Ctrl-Shift-V",  # Shortcut
            "Automatically synchronize selection with the current location in other views",  # Tooltip
        )
        ok = idaapi.register_action(action_desc)
        idaapi.update_action_checkable(self.synchronization_action_name, True)
        idaapi.update_action_checked(
            self.synchronization_action_name, self.view_hooks.enabled
        )
        assert ok, f"Failed to register action {self.synchronization_action_name}"

    def Show(self, modal=False):
        if super().Show(modal=modal) >= 0:
            added = idaapi.attach_action_to_popup(
                self.GetWidget(), None, self.highlight_all_action_name
            )
            assert added, (
                f"Failed to attach action {self.highlight_all_action_name} to popup"
            )
            added = idaapi.attach_action_to_popup(
                self.GetWidget(), None, self.synchronization_action_name
            )
            assert added, (
                f"Failed to attach action {self.synchronization_action_name} to popup"
            )
            return True
        return False

    def toggle_highlight_all_matches(self):
        self.highlight_all_matches = not self.highlight_all_matches
        idaapi.update_action_checked(
            self.highlight_all_action_name, self.highlight_all_matches
        )

        if self.highlight_all_matches:
            if self.view_hooks.all_ranges is None:
                self.view_hooks.build_all_ranges()
            if (
                self.view_hooks.all_ranges is not None
            ):  # Ensure all_ranges is not None before iterating
                for ra in self.view_hooks.all_ranges:
                    self.add_highlight(ra.start_ea, ra.size())
        else:
            self.clear_highlight()

        idaapi.refresh_idaview_anyway()

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
        idaapi.unregister_action(self.highlight_all_action_name)
        idaapi.unregister_action(self.synchronization_action_name)
        return super().OnClose()

    def OnSelectionChange(self, sel: list[int] | int):
        if self.highlight_all_matches:
            return

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


class HighlightAllMatchesHandler(idaapi.action_handler_t):
    def __init__(self, chooser):
        super().__init__()
        self.chooser = chooser

    def activate(self, ctx: idaapi.action_ctx_base_t):
        self.chooser.toggle_highlight_all_matches()
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        return idaapi.AST_ENABLE_ALWAYS


class EnableViewHooksHandler(idaapi.action_handler_t):
    def __init__(self, view_hooks):
        super().__init__()
        self.view_hooks = view_hooks

    def activate(self, ctx):
        self.view_hooks.enabled = not self.view_hooks.enabled
        idaapi.update_action_checked(
            f"enable_view_hooks_{id(self.view_hooks.chooser)}", self.view_hooks.enabled
        )
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        return idaapi.AST_ENABLE_ALWAYS


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
                            e.cpx = (
                                self.hex_prefix_length + 3 * (rel_idx) + (rel_idx > 7)
                            )
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
