# -*- coding: utf-8 -*-
#
# An OutputFilter transforms the output from OSXCollector.
# Every filter must derive from OutputFilter.
#

import os
import sys

import simplejson
import yaml
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.exceptions import MissingConfigError


class OutputFilter(object):

    """An OutputFilter transforms the output from OSXCollector.

    Attributes:
        _config: An instance of the Config
    """

    def __init__(self):
        self.config = Config(self.__class__.__name__)

    def filter_line(self, blob):
        """Each Line of osxcollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swalling the line.

        Args:
            blob: A dict representing one line of output from osxcollector

        Returns:
            A dict or None
        """
        return blob

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter can do any batch processing on that requires the complete input.

        Returns:
            An array of dicts (empty array if no lines remain)
        """
        return []


class Config(object):

    """Reads a config for the filter

    Config is read from a YAML file named `osxcollector.yaml`

    The file will be searched for first in the current directory, then in the
    home directory for the user, then by reading the OSXCOLLECTOR_CONF environment var.
    """

    def __init__(self, filter_name):

        self._config = None
        for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF'):
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
            key - A string in the 'parentKey.subKey.andThenUnderThat' format.
            default - A default value to return if the key does not exist.

        Raises:
            MissingConfigError - when key does not exist and no default is supplied.
        """
        full_key = '{0}.{1}'.format(self._filter_name, key)
        return self.get_config(full_key, default)

    def get_config(self, key, default=None):
        """Reads config from a top level key.

        Arguments:
            key - A string in the 'parentKey.subKey.andThenUnderThat' format.
            default - A default value to return if the key does not exist.

        Raises:
            MissingConfigError - when key does not exist and no default is supplied.
        """
        val = DictUtils.get_deep(self._config, key, default)
        if not val:
            raise MissingConfigError('Missing value[{0}]'.format(key))
        return val


def run_filter(output_filter):
    """Feeds stdin to an instance of OutputFilter and spews to stdout.

    Args:
        output_filter: An instance of an OutputFilter
    """
    def _unbuffered_stdin():
        """Unbuffered read allows lines to be processed before EOF is reached"""
        line = sys.stdin.readline()
        while bool(line):
            yield line.decode('latin-1', errors='ignore').encode('utf-8', errors='ignore')
            line = sys.stdin.readline()

    for json_string in _unbuffered_stdin():
        try:
            blob = simplejson.loads(json_string)
        # TODO: Just catch a simplejson failure
        except Exception:
            continue

        blob = output_filter.filter_line(blob)
        if blob:
            sys.stdout.write(simplejson.dumps(blob))
            sys.stdout.write('\n')

    final_blobs = output_filter.end_of_lines()
    for blob in final_blobs:
        sys.stdout.write(simplejson.dumps(blob))
        sys.stdout.write('\n')
