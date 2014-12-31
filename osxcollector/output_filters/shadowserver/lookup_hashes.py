#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupHashesFilter uses ShadowServer to lookup the values in 'sha1' and add 'osxcollector_shadowserver' key.
#
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.shadowserver.api import ShadowServerApi


class LookupHashesFilter(ThreatFeedFilter):

    """A class to lookup hashes using ShadowServer API."""

    def __init__(self, lookup_when=None, cache_file_name=None):
        super(LookupHashesFilter, self).__init__('sha1', 'osxcollector_shadowserver', lookup_when=lookup_when)
        self._cache_file_name = cache_file_name

    def _lookup_iocs(self, all_iocs):
        """Looks up the ShadowServer info for a set of hashes.

        Args:
            all_iocs - a list of hashes.
        Returns:
            A dict with hash as key and threat info as value
        """
        ss = ShadowServerApi(cache_file_name=self._cache_file_name)
        return ss.get_bin_test(all_iocs)

    def _should_add_threat_info_to_blob(self, blob, threat_info):
        """Only add info from ShadowServer if the hash and the filename match.

        Args:
            blob - A dict of data representing a line of output from OSXCollector
            threat_info - The threat info from ShadowServer
        Returns:
            boolean
        """
        if blob.get('file_path', '').endswith(threat_info.get('filename', '')):
            return True
        return False


def main():
    cache_file_name = './shadowserver_cache.json'
    run_filter(LookupHashesFilter(cache_file_name=cache_file_name))


if __name__ == "__main__":
    main()
