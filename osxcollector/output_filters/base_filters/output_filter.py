# -*- coding: utf-8 -*-
#
# An OutputFilter transforms the output from OSXCollector. Every filter must derive from OutputFilter.
#
# _run_filter is a default implementation of a main that reads input from stdin, feeds it to an OutputFilter, and
# spits the output to stdout.
#
import sys
from argparse import ArgumentParser

import simplejson

from osxcollector.output_filters.util.error_messages import write_exception


class OutputFilter(object):

    """An OutputFilter transforms the output from OSXCollector. Every filter must derive from OutputFilter.

    The basic flow of data through an OutputFilter:
    - Each line of OSXCollector output is passed to OutputFilter.filter_line
    - After all lines have been passed to filter_line, a final call is made OutputFilter.to end_of_lines

    There are two common ways a filter deals with lines:
    - A filter that modifies each line independent of other lines could simply implement filter_line.
    - A filter that modifies each line based on other lines may want to accumulate lines until end_of_lines is called,
      then bulk operate on all lines at once.

    OutputFilters use the words 'line' or 'blob' to refer to OSXCollector output.
    """

    def __init__(self, **kwargs):
        """Skeleton for __init__

        Args:
            kwargs: Variable arguments are used to pass filter specific args to OutputFilters.
        """
        pass

    def filter_line(self, blob):
        """Each Line of OSXCollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swallowing the line.

        Args:
            blob: A dict representing one line of output from OSXCollector.
        Returns:
            A dict or None
        """
        return blob

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter performs any processing that requires the complete input to have already been fed.

        Returns:
            An enumerable of dicts
        """
        return []

    def get_argument_parser(self):
        """Describes commandline arguments for this OutputFilter.

        The names of the `dest` param for the argument in the ArgumentParser must match the name of positional or
        named arguments in `__init__`

        Returns:
            An `argparse.ArgumentParser`
        """
        return None


def _unbuffered_input(read_from):
    """A generator to allow lines to be read before EOF is reached.

    Args:
        read_from: A stream to read from
    Returns:
        yields strings
    """
    line = read_from.readline()
    while bool(line):
        yield line.decode('latin-1', errors='ignore').encode('utf-8', errors='ignore')
        line = read_from.readline()


def _run_filter(output_filter, input_stream=None, output_stream=None, *args, **kwargs):
    """Feeds stdin to an instance of OutputFilter and spews to stdout.

    Args:
        output_filter: An instance of OutputFilter.
        input_stream: Where to read input from.
        output_stream: Where to write output to.
    """
    if not input_stream:
        input_stream = sys.stdin
    if not output_stream:
        output_stream = sys.stdout

    for json_string in _unbuffered_input(input_stream):
        try:
            blob = simplejson.loads(json_string)
        except simplejson.JSONDecodeError as e:
            write_exception(e)
            continue

        blob = output_filter.filter_line(blob)
        if blob:
            output_stream.write(simplejson.dumps(blob))
            output_stream.write('\n')

    final_blobs = output_filter.end_of_lines()
    for blob in final_blobs:
        output_stream.write(simplejson.dumps(blob))
        output_stream.write('\n')

    output_stream.flush()


def run_filter_main(output_filter_cls):
    """A `main` method with runs an OutputFilter.

    Args:
        output_filter_cls: Class name of the OutputFilter
    """
    filter_arguments = output_filter_cls().get_argument_parser()
    argument_parents = [filter_arguments] if filter_arguments else []

    parser = ArgumentParser(parents=argument_parents, conflict_handler='resolve')
    parser.add_argument('-i', '--input-file', dest='input_file', default=None,
                        help='[OPTIONAL] Path to OSXCollector output to read. Defaults to stdin otherwise.')
    args = parser.parse_args()

    output_filter = output_filter_cls(**vars(args))

    if args.input_file:
        with(open(args.input_file, 'r')) as fp_in:
            _run_filter(output_filter, input_stream=fp_in)
    else:
        _run_filter(output_filter)
