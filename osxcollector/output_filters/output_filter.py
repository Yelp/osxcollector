# -*- coding: utf-8 -*-
import os
import sys
import yaml

import simplejson


class OutputFilter(object):

    """An OutputFilter transforms the output from OSXCollector."""

    def __init__(self):
        """Reads a dict of config for the filter

        Config is read from a YAML file named `osxcollector.yaml`

        The file will be searched for first in the current directory, then in the
        home directory for the user, then by reading the OSXCOLLECTOR_CONF environment var.

        The config for each filter is it's own top level key in the YAML file.
        The name of the toplevel key is the name of the filter class.
        """
        self._config = None

        full_config = None
        for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF'):
            try:
                with open(os.path.join(loc, 'osxcollector.yaml')) as source:
                    full_config = yaml.load(source.read())
                    break
            except IOError:
                pass

        if full_config:
            self._config_section = self.__class__.__name__
            self._config = full_config.get(self._config_section)

    def get_config(self, key, default=None):
        try:
            return self._config[key]
        except Exception:
            if default is not None:
                return default

            raise MissingConfigError('Missing value[{0}] from config section[{1}]'.format(key, self._config_section))

    def filter_line(self, blob):
        """Each Line of osxcollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swalling the line.

        Args:
            output_line: A dict

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


class MissingConfigError(Exception):

    """An error to throw when configuration is missing"""
    pass


def _unbuffered_stdin():
    """Unbuffered read allows lines to be processed before EOF is reached"""
    line = sys.stdin.readline()
    while bool(line):
        yield line.decode('latin-1')
        line = sys.stdin.readline()


def run_filter(output_filter):
    """Feeds stdin to an instance of OutputFilter and spews to stdout.

    Args:
        output_filter: An instance of an OutputFilter
    """
    for json_string in _unbuffered_stdin():
        try:
            blob = simplejson.loads(json_string)
        except Exception:
            pass

        blob = output_filter.filter_line(blob)
        if blob:
            sys.stdout.write(simplejson.dumps(blob))
            sys.stdout.write('\n')

    final_blobs = output_filter.end_of_lines()
    for blob in final_blobs:
        sys.stdout.write(simplejson.dumps(blob))
        sys.stdout.write('\n')
