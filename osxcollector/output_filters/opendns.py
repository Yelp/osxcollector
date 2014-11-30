#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import simplejson
import investigate
import urlparse

from osxcollector.output_filters.threat_feed import ThreatFeedFilter
from osxcollector.output_filters.output_filter import run_filter


class OpenDNSFilter(ThreatFeedFilter):
    """A class to find suspicious domains using OpenDNS Investigate API."""

    # Domain categories to consider suspicious
    SUSPICIOUS_CATEGORIES = [
        'Adware',
        'Botnet', 
        'Typo Squatting', 
        'Drive-by Downloads/Exploits', 
        'Mobile Threats', 
        'High Risk Sites and Locations',
        'Malware', 
        'Phishing'
        ]

    def __init__(self):
        super(OpenDNSFilter, self).__init__('osxcollector_domains', 'osxcollector_opendns')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        opendns = investigate.Investigate(self._api_key)
        categorized = opendns.categorization(list(self._all_iocs), labels=True)

        for domain in categorized.keys():
            if self._is_suspicious(categorized[domain]):
                self._threat_info_by_iocs[domain] = {
                    'categorization': categorized[domain],
                    'security': opendns.security(domain)
                }

    @classmethod
    def _is_suspicious(cls, opendns_info):
        """Analyzes info from opendns and makes a boolean determination of suspicious or not.

        Args:
            opendns_info: The result of a call to opendns.categorization
        Returns:
            boolean
        """
        # Categorization of site
        if -1 == opendns_info['status']:
            return True 
        if any([cat in cls.SUSPICIOUS_CATEGORIES for cat in opendns_info['content_categories']]): # 
            return True
        if any([cat in cls.SUSPICIOUS_CATEGORIES for cat in opendns_info['security_categories']]):
            return True

        # TODO: handle security info
        return False


def main():
    run_filter(OpenDNSFilter())


if __name__ == "__main__": 
    main()
