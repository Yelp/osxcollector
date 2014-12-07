#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupDomainsFilter uses VirusTotal to lookup the values in 'md5' and add 'osxcollector_virustotal' key.
#
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupHashesFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(LookupHashesFilter, self).__init__('md5', 'osxcollector_vt_hashes',
                                                 only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                                 api_key='virustotal')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_domain_reports(self._all_iocs)

        for md5 in reports.keys():
            report = reports[md5]
            if 1 == report.get('response_code'):
                self._threat_info_by_iocs[md5] = reports[md5]


def main():
    run_filter(LookupHashesFilter())


if __name__ == "__main__":
    main()
