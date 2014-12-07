#!/usr/bin/env python
# -*- coding: utf-8 -*-
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.output_filter import run_filter
from osxcollector.output_filters.threat_feed import ThreatFeedFilter
from virus_total_apis import PublicApi


class VTHashesFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(VTHashesFilter, self).__init__('md5', 'osxcollector_vt_hashes',
                                             only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                             api_key='virustotal')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = PublicApi(self._api_key)

        for ioc in self._all_iocs:
            report = vt.get_file_report(ioc)
            if DictUtils.get_deep(report, 'results.scans'):
                del report['results']['scans']
            self._threat_info_by_iocs[ioc] = report


def main():
    run_filter(VTHashesFilter())


if __name__ == "__main__":
    main()
