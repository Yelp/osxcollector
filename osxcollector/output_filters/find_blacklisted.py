#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# FindBlacklistedFilter adds 'osxcollector_blacklist' key to lines matching a blacklist.
#
import re

from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.base_filters. \
    output_filter import MissingConfigError
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.find_domains import clean_domain


class FindBlacklistedFilter(OutputFilter):

    """Adds 'osxcollector_blacklist' key to lines matching a blacklist.

    This filters compares each line to a set of blacklists and marks lines that match the blacklist.
    This is proving useful for filtering known hashes, known bad filenames, known bad domains, etc.

    Configuation Keys:
        blacklist_name       - [REQUIRED] the name of the blacklist
        blacklist_keys       - [REQUIRED] get the value of these keys and compare against the blacklist
        blacklist_is_regex   - [REQUIRED] should the values in the blacklist file be treated as regex
        blacklist_file_path  - [REQUIRED] path to a file with the actual values to blacklist
        blacklist_is_domains - [OPTIONAL] interpret values as domains and do some smart regex and subdomain stuff with them
    """

    def __init__(self):
        super(FindBlacklistedFilter, self).__init__()
        self._blacklists = self._init_blacklists()

    def _init_blacklists(self):
        """Reads the config and builds a list of blacklist dictionaries.

        The blacklist config is sufficiently complex that much of this method deals with simply validating config

        Returns:
            A list of config dicts.
        Raises:
            MissingConfigError - when required key does not exist.
        """
        blacklists = []
        for config_chunk in self.config.get_config('blacklists'):

            required_keys = ['blacklist_name', 'blacklist_keys', 'blacklist_is_regex', 'blacklist_file_path']
            if not all([key in config_chunk.keys() for key in required_keys]):
                raise MissingConfigError('Blacklist config is missing a required key.\nRequired keys are: {0}'.format(repr(required_keys)))

            if not isinstance(config_chunk['blacklist_keys'], list):
                raise MissingConfigError('The value of \'blacklist_keys\' in Blacklist config must be a list')

            try:
                blacklist_is_domains = config_chunk.get('blacklist_is_domains', False)
                is_regex = blacklist_is_domains or config_chunk['blacklist_is_regex']

                with open(config_chunk['blacklist_file_path'], 'r') as value_file:
                    blacklisted_values = []
                    for line in value_file.readlines():
                        if not line.startswith('#'):
                            line = line.rstrip('\n')
                            if line:
                                blacklisted_values.append(line)
                    if is_regex:
                        blacklisted_values = [self._convert_to_regex(val, blacklist_is_domains) for val in blacklisted_values]
                    config_chunk['blacklist_values'] = blacklisted_values
            except IOError as e:
                raise MissingConfigError(e.msg)

            blacklists.append(config_chunk)

        return blacklists

    def _convert_to_regex(self, blacklisted_value, blacklist_is_domains):
        """Convert a blacklisted_value to a regex.

        Args:
            blacklisted_value - string of value on a blacklist
            blacklist_is_domains - Boolean if true, the blacklisted_value is treated as a domain.
        Returns:
            a compliled regex object
        """
        if blacklist_is_domains:
            domain = clean_domain(blacklisted_value)
            blacklisted_value = '(.+\.)?{0}'.format(domain.replace('.', '\.').replace('-', '\-'))
        return re.compile(blacklisted_value)

    def filter_line(self, blob):
        """Find blacklisted values in a line.

        Lines are never cached, every line in produces a line out.
        """
        for config_chunk in self._blacklists:
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
                        if any([regex_to_match.search(val) for regex_to_match in config_chunk['blacklist_values']]):
                            found_match = True
                    else:
                        if any([val_to_match == val for val_to_match in config_chunk['blacklist_values']]):
                            found_match = True

                if found_match:
                    blob.setdefault('osxcollector_blacklist', [])
                    blob['osxcollector_blacklist'].append(config_chunk['blacklist_name'])
                    break

        return blob


def main():
    run_filter(FindBlacklistedFilter())


if __name__ == "__main__":
    main()
