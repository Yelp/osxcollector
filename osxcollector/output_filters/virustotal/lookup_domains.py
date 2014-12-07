#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupDomainsFilter uses VirusTotal to lookup the values in 'osxcollector_domains' and add 'osxcollector_virustotal' key.
#
import sys

import simplejson
from osxcollector.output_filters.ase_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupDomainsFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(LookupDomainsFilter, self).__init__('osxcollector_domains', 'osxcollector_vt_domains',
                                                  only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                                  api_key='virustotal')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_domain_reports(self._all_iocs)
        for domain in reports.keys():
            report = reports[domain]
            if 1 == report.get('response_code'):
                self._threat_info_by_iocs[domain] = reports[domain]
        sys.stderr.write(simplejson.dumps(reports, indent=2))


def main():
    run_filter(LookupDomainsFilter())


if __name__ == "__main__":
    main()
