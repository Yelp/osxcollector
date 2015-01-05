#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupURLsFilter uses VirusTotal to lookup the URLs in 'LSQuarantineDataURLString' and add 'osxcollector_vturl' key.
#
import re

from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupURLsFilter(ThreatFeedFilter):

    """A class to find suspicious URLs using VirusTotal API."""

    SCHEMES = re.compile('https?')

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        lookup_when_url_scheme_matches = self._generate_only_lookup_when(only_lookup_when)
        super(LookupURLsFilter, self).__init__('LSQuarantineDataURLString', 'osxcollector_vturl',
                                                 only_lookup_when=lookup_when_url_scheme_matches, is_suspicious_when=is_suspicious_when,
                                                 api_key='virustotal')

    def _generate_only_lookup_when(self, only_lookup_when):
        """Generates functions that checks whether the blob contains a valid URL
        in LSQuarantineDataURLString field.
        """
        def check_url_scheme(blob):
            return self.SCHEMES.match(blob.get('LSQuarantineDataURLString')) and (not only_lookup_when or only_lookup_when(blob))
        return check_url_scheme

    def _lookup_iocs(self):
        """Looks up the VirusTotal report for a set of URLs"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_url_reports(self._all_iocs)

        for url in reports.keys():
            trimmed_report = self._trim_url_report(reports[url])
            if self._should_store_ioc_info(trimmed_report):
                self._threat_info_by_iocs[url] = trimmed_report

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
    run_filter(LookupURLsFilter())


if __name__ == "__main__":
    main()
