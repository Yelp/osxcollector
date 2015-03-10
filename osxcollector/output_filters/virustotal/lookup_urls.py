#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# LookupURLsFilter uses VirusTotal to lookup the URLs in 'LSQuarantineDataURLString' and add 'osxcollector_vturl' key.
#
import re

from threat_intel import VirusTotalApi

from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.base_filters.threat_feed import ThreatFeedFilter
from osxcollector.output_filters.util.config import config_get_deep


class LookupURLsFilter(ThreatFeedFilter):

    """A class to find suspicious URLs using VirusTotal API."""

    SCHEMES = re.compile('https?')

    def __init__(self, lookup_when=None, **kwargs):
        lookup_when_url_scheme_matches = self._generate_lookup_when(lookup_when)
        super(LookupURLsFilter, self).__init__('LSQuarantineDataURLString', 'osxcollector_vturl',
                                               lookup_when=lookup_when_url_scheme_matches,
                                               name_of_api_key='virustotal', **kwargs)

    def _generate_lookup_when(self, only_lookup_when):
        """Generates functions that checks whether the blob contains a valid URL
        in LSQuarantineDataURLString field.
        """
        def check_url_scheme(blob):
            return self.SCHEMES.match(blob['LSQuarantineDataURLString']) and (not only_lookup_when or only_lookup_when(blob))
        return check_url_scheme

    def _lookup_iocs(self, all_iocs, resource_per_req=25):
        """Caches the VirusTotal info for a set of URLs.

        Args:
            all_iocs - a list of URLs.
        Returns:
            A dict with URL as key and threat info as value
        """
        threat_info = {}

        cache_file_name = config_get_deep('virustotal.LookupURLsFilter.cache_file_name', None)
        vt = VirusTotalApi(self._api_key, resource_per_req, cache_file_name=cache_file_name)
        reports = vt.get_url_reports(all_iocs)

        for url in reports.keys():
            report = reports[url]
            if not report:
                continue
            if self._should_store_ioc_info(report):
                threat_info[url] = self._trim_url_report(report)

        return threat_info

    def _should_store_ioc_info(self, report, min_hits=1):
        """Only store if the hash has > min_hits positive detections.

        Args:
            report - A dict response from get_url_reports
            min_hits - Minimum number of VT positives
        Returns:
            boolean
        """
        return 1 == report.get('response_code') and min_hits < report.get('positives', 0)

    def _trim_url_report(self, report):
        """Copy just the required keys from the report into a new report.

        Args:
            report - A dict response from get_url_reports
        Returns:
            A smaller dict
        """
        copy_keys = [
            'scan_id',
            'resource',
            'url',
            'scan_date',
            'permalink',
            'positives',
            'total',
            'response_code'
        ]

        return dict([(key, report.get(key)) for key in copy_keys])


def main():
    run_filter_main(LookupURLsFilter)


if __name__ == "__main__":
    main()
