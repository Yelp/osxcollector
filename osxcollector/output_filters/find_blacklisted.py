#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# FindBlacklistedFilter adds 'osxcollector_blacklist' key to lines matching a blacklist.
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.util.blacklist import create_blacklist
from osxcollector.output_filters.util.config import config_get_deep


class FindBlacklistedFilter(OutputFilter):

    """Adds 'osxcollector_blacklist' key to lines matching a blacklist.

    This filters compares each line to a set of blacklists and marks lines that match the blacklist.
    This is proving useful for filtering known hashes, known bad filenames, known bad domains, etc.

    Configuration Keys:
        blacklist_name       - [REQUIRED] the name of the blacklist
        blacklist_keys       - [REQUIRED] get the value of these keys and compare against the blacklist
        blacklist_is_regex   - [REQUIRED] should the values in the blacklist file be treated as regex
        blacklist_file_path  - [REQUIRED] path to a file with the actual values to blacklist
        blacklist_is_domains - [OPTIONAL] interpret values as domains and do some smart regex and subdomain stuff with them
    """

    def __init__(self, **kwargs):
        super(FindBlacklistedFilter, self).__init__(**kwargs)
        self._blacklists = self._init_blacklists()

    def _init_blacklists(self):
        """Reads the config and builds a list of blacklists."""
        return [create_blacklist(config_chunk) for config_chunk in config_get_deep('blacklists')]

    def filter_line(self, blob):
        """Find blacklisted values in a line.

        Lines are never cached, every line in produces a line out.
        """
        for blacklist in self._blacklists:
            matching_term = blacklist.match_line(blob)
            if matching_term:
                blob.setdefault('osxcollector_blacklist', {})
                blob['osxcollector_blacklist'].setdefault(blacklist.name, [])
                blob['osxcollector_blacklist'][blacklist.name].append(matching_term)
                break

        return blob


def main():
    run_filter_main(FindBlacklistedFilter)


if __name__ == "__main__":
    main()
