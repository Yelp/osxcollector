# -*- coding: utf-8 -*-
import sys


class OutputFilter(object):
    """An OutputFilter transforms the output from OSXCollector."""

    def filter_line(self, line):
        """Each line of output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swalling the line.

        Args:
            line: A string line of output

        Returns:
            A string or None
        """
        return line

    def end_of_lines(self):
        """Called after all output has been fed to filter_line.

        The OutputFilter can do any batch processing on that requires the complete input.

        Returns:
            An array of strings or None
        """
        return None

def run_filter(output_filter):
    """Feeds stdin to an instance of OutputFilter and spews to stdout.

    Args:
        output_filter: An instance of an OutputFilter
    """
    for line in sys.stdin.readlines():
        line = output_filter.filter_line(line)
        if line:
            sys.stdout.write(line)

    final_lines = output_filter.end_of_lines()
    if final_lines:
        for line in final_lines:
            sys.stdout.write(line)