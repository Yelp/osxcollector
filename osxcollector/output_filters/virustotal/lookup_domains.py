#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# LookupDomainsFilter uses VirusTotal to lookup the values in 'osxcollector_domains' and add 'osxcollector_virustotal' key.
#
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.base_filters. \
    threat_feed import ThreatFeedFilter
from osxcollector.output_filters.virustotal.api import VirusTotalApi


class LookupDomainsFilter(ThreatFeedFilter):

    """A class to find suspicious hashes using VirusTotal API."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(LookupDomainsFilter, self).__init__('osxcollector_domains', 'osxcollector_virustotal',
                                                  only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                                  api_key='virustotal')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        vt = VirusTotalApi(self._api_key)
        reports = vt.get_domain_reports(self._all_iocs)
        for domain in reports.keys():

            # TODO(ivanlei): Should score the VT results here and only add them if they're interesting
            self._threat_info_by_iocs[domain] = self._trim_domain_report(domain, reports[domain])

    def _trim_domain_report(self, domain, initial_report):
        trimmed_report = {}

        sample_keys = [
            ('undetected_referrer_samples', 0),
            ('undetected_communicating_samples', 0),
            ('detected_downloaded_samples', 2),
            ('detected_referrer_samples', 2),
            ('detected_communicating_samples', 2),
            ('detected_urls', 2),
        ]
        for sample_key, threshold in sample_keys:
            for sample in initial_report.get(sample_key, []):
                if sample.get('positives') >= threshold:
                    trimmed_report.setdefault(sample_key, [])
                    trimmed_report[sample_key].append(sample)

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
        if len(categorization):
            trimmed_report['categorization'] = categorization

        domain_info_keys = [
            'resolutions',
            'whois',
            'whois_timestamp',
            'subdomains'
        ]
        domain_info = {}
        for copy_key in domain_info_keys:
            if copy_key in initial_report:
                domain_info[copy_key] = initial_report[copy_key]
                if 'whois' == copy_key:
                    domain_info[copy_key] = domain_info[copy_key].split('\n')

        if len(domain_info):
            trimmed_report['domain_info'] = domain_info

        just_copy_keys = [
            'response_code',
            'pcaps'
        ]
        for copy_key in just_copy_keys:
            if copy_key in initial_report:
                trimmed_report[copy_key] = initial_report[copy_key]

        trimmed_report['domain'] = domain


def main():
    run_filter(LookupDomainsFilter())


if __name__ == "__main__":
    main()
