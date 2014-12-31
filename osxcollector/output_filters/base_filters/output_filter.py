# -*- coding: utf-8 -*-
#
# An OutputFilter transforms the output from OSXCollector. Every filter must derive from OutputFilter.
#
# Config is a very simplistic class for reading YAML config.
#
# run_filter is a default implementation of a main that reads input from stdin, feeds it to an OutputFilter, and
# spits the output to stdout.
#
import os
import sys

import simplejson
import yaml
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.exceptions import MissingConfigError
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

    Attributes:
        config: An instance of the Config
    """

    def __init__(self):
        self.config = Config(self.__class__.__name__)

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


class Config(object):

    """Config is a simple YAML reader for OutputFilters.

    The YAML file must be named `osxcollector.yaml`

    The file will be searched for first in the current directory, then in the
    home directory for the user, then by reading the OSXCOLLECTOR_CONF environment var.
    """

    def __init__(self, filter_name):
        """Reads and parses the YAML file.

        Args:
            filter_name: String class name of the filter instantiating this instance of Config.
        """
        self._config = None
        for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF', ''):
            try:
                with open(os.path.join(loc, 'osxcollector.yaml')) as source:
                    self._config = yaml.load(source.read())
                    break
            except IOError:
                pass

        if self._config:
            self._filter_name = filter_name

    def get_filter_config(self, key, default=None):
        """Reads config from subsection of the YAML with the same name as the filter class.

        Arguments:
            key: A string in the 'parentKey.subKey.andThenUnderThat' format.
            default: A default value to return if the key is not present.
        Returns:
            The value of the key or default when the key is not present.
        Raises:
            MissingConfigError: when key does not exist and no default is supplied.
        """
        full_key = '{0}.{1}'.format(self._filter_name, key)
        return self.get_config(full_key, default)

    def get_config(self, key, default=None):
        """Reads config from a top level key.

        Arguments:
            key: A string in the 'parentKey.subKey.andThenUnderThat' format.
            default: A default value to return if the key is not present.
        Returns:
            The value of the key or default when the key is not present.
        Raises:
            MissingConfigError: when key does not exist and no default is supplied.
        """
        val = DictUtils.get_deep(self._config, key, default)
        if not val:
            raise MissingConfigError('Missing value[{0}]'.format(key))
        return val


def run_filter(output_filter, input_stream=None, output_stream=None):
    """Feeds stdin to an instance of OutputFilter and spews to stdout.

    Args:
        output_filter: An instance of OutputFilter.
        input_stream: Where to read input from.
        output_stream: Where to write output to.
    """
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
