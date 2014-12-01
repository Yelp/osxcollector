#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import simplejson

from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.output_filter import MissingConfigError
from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.output_filter import run_filter


class BlacklistFilter(OutputFilter):

    """Adds 'osxcollector_blacklist' key to lines matching a blacklist.

    This filters compares each line of input to a set of blacklists and marks lines
    that match the blacklist. This is useful for filtering known hashes, known bad kext, bad domains, etc.
    """

    def __init__(self):
        super(BlacklistFilter, self).__init__()
        self._blacklist_config = self._init_config()

    def _init_config(self):
        """Reads the config and builds a list of config dictionaries.

        The blacklist config is sufficiently complex that much of this method deals with simply validating config

        Returns:
            A list of config dicts. Each dict has the keys (blacklist_name, blacklist_keys, blacklist_values, blacklist_is_regex)
        """
        blacklist_config = []
        for config_chunk in self.get_config('blacklists'):

            required_keys = ['blacklist_name', 'blacklist_keys', 'blacklist_is_regex', 'value_file']
            if not all([key in config_chunk.keys() for key in required_keys]):
                raise MissingConfigError('Blacklist config is missing a required key.\nRequired keys are: {0}'.format(repr(required_keys)))

            if not isinstance(config_chunk['blacklist_keys'], list):
                raise MissingConfigError('The value of \'blacklist_keys\' in Blacklist config must be a list')

            try:
                with open(config_chunk['value_file'], 'r') as value_file:
                    lines = [line.rstrip('\n') for line in value_file.readlines() if not line.startswith('#')]
                    if config_chunk['blacklist_is_regex']:
                        lines = [re.compile(line) for line in lines]
                    del config_chunk['value_file']
                    config_chunk['blacklist_values'] = lines
            except IOError as e:
                raise MissingConfigError(e.msg)

            blacklist_config.append(config_chunk)

        return blacklist_config

    def filter_line(self, line):
        """Find blacklisted values in a line."""
        try:
            blob = simplejson.loads(line)
        except Exception:
            return line

        for config_chunk in self._blacklist_config:
            for key in config_chunk['blacklist_keys']:
                values = DictUtils.get_deep(blob, key)
                if not values:
                    continue
                if not isinstance(values, list):
                    values = [values]

                found_match = False
                for val in values:
                    if found_match:
                        break

                    if config_chunk['blacklist_is_regex']:
                        if any([regex_to_match.match(val) for regex_to_match in config_chunk['blacklist_values']]):
                            found_match = True
                    else:
                        if any([val_to_match == val for val_to_match in config_chunk['blacklist_values']]):
                            found_match = True

                if found_match:
                    blob.setdefault('osxcollector_blacklist', [])
                    blob['osxcollector_blacklist'].append(config_chunk['blacklist_name'])
                    line = '{0}\n'.format(simplejson.dumps(blob))
                    break

        return line


def main():
    run_filter(BlacklistFilter())


if __name__ == "__main__":
    main()
