#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupDomainsFilter uses VirusTotal to lookup the values in 'md5' and add 'osxcollector_vthash' key.
#
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupHashesFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(LookupHashesFilter, self).__init__('sha2', 'osxcollector_vthash',
                                                 only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                                 api_key='virustotal')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_file_reports(self._all_iocs)

        for hash_val in reports.keys():
            report = reports[hash_val]

            if self._should_store_ioc_info(report):
                self._threat_info_by_iocs[hash_val] = self._trim_hash_report(reports[hash_val])

    def _should_store_ioc_info(self, report):
        return 1 == report.get('response_code') and 1 < report.get('positives', 0)

    def _trim_hash_report(self, report):
        copy_keys = [
            'scan_id',
            'sha1',
            'sha256',
            'md5',
            'scan_date',
            'permalink',
            'positives',
            'total',
            'response_code'
        ]

        return dict([(key, report.get(key)) for key in copy_keys])


def main():
    run_filter(LookupHashesFilter())


if __name__ == "__main__":
    main()
