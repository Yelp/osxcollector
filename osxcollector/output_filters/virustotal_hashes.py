#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import simplejson
import urlparse
from time import sleep

from osxcollector.output_filters.threat_feed import ThreatFeedFilter
from osxcollector.output_filters.output_filter import run_filter

from virus_total_apis import PublicApi 


class VTHashesFilter(ThreatFeedFilter):
    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self):
        super(VTHashesFilter, self).__init__('md5', 'osxcollector_vt_hashes')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = PublicApi(self._api_key)

        for ioc in self._all_iocs:
            report = vt.get_file_report(ioc)
            self._threat_info_by_iocs[ioc] = report
            sleep(15)

def main():
    run_filter(VTHashesFilter())


if __name__ == "__main__": 
    main()
