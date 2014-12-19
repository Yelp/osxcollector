#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupDomainsFilter uses VirusTotal to lookup the values in 'osxcollector_domains' and add 'osxcollector_vtdomain' key.
#
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.find_blacklisted import create_blacklist
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupDomainsFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(LookupDomainsFilter, self).__init__('osxcollector_domains', 'osxcollector_vtdomain',
                                                  only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                                  api_key='virustotal')
        self._whitelist = create_blacklist(self.config.get_config('domain_whitelist'))

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_domain_reports(self._all_iocs)
        for domain in reports.keys():
            if self._whitelist.match_values(domain):
                continue

            trimmed_report = self._trim_domain_report(domain, reports[domain])
            if self._should_store_ioc_info(trimmed_report):
                self._threat_info_by_iocs[domain] = trimmed_report

    def _should_store_ioc_info(self, trimmed_report):
        """Decide whether a report from VT is interesting enough to store in the output.

        Args:
            trimmed_report: A dict of data from VT
        Returns:
            boolean
        """
        sample_keys = [
            ('detected_downloaded_samples', 3),
            ('detected_referrer_samples', 3),
            ('detected_communicating_samples', 3),
            ('detected_urls', 3),
        ]
        detections = trimmed_report.get('detections', {})
        for sample_key, threshold in sample_keys:
            if detections.get(sample_key, 0) >= threshold:
                return True
        return False

    def _trim_domain_report(self, domain, initial_report):
        """Reorganizes and compacts a VT domain report.

        Args:
            domain - string domain name
            initial_report - dict result of calling VirusTotalApi.get_domain_reports for the domain

        Returns:
            A reorganized and compacted dict.
        """
        trimmed_report = {}

        sample_keys = [
            'undetected_referrer_samples',
            'undetected_communicating_samples',
            'detected_downloaded_samples',
            'detected_referrer_samples',
            'detected_communicating_samples',
            'detected_urls',
        ]
        detections = {}
        for sample_key in sample_keys:
            detections[sample_key] = len(initial_report.get(sample_key, []))
        trimmed_report['detections'] = detections

        categorization_keys = [
            'categories',
            'BitDefender category',
            'BitDefender domain info',
            'Websense ThreatSeeker category',
            'Webutation domain info',
            'WOT domain info',
            'TrendMicro category'
        ]
        categorization = {}
        for copy_key in categorization_keys:
            if copy_key in initial_report:
                categorization[copy_key] = initial_report[copy_key]
        trimmed_report['categorization'] = categorization

        just_copy_keys = [
            'response_code',
        ]
        for copy_key in just_copy_keys:
            if copy_key in initial_report:
                trimmed_report[copy_key] = initial_report[copy_key]

        trimmed_report['domain'] = domain

        return trimmed_report


def main():
    run_filter(LookupDomainsFilter())


if __name__ == "__main__":
    main()
