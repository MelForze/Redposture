"""The public terminal palette uses one red and one green variant."""

from redposture_core.console import _COLORS as CONSOLE_COLORS
from redposture_core.logger import _COLORS as LOGGER_COLORS


def test_old_red_and_green_aliases_are_not_in_output_palettes():
    for palette in (CONSOLE_COLORS, LOGGER_COLORS):
        assert "red" not in palette
        assert "green" not in palette
        assert palette["true_red"] == "1;38;5;196"
        assert palette["bright_green"] == "1;92"
