#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import simplejson
import investigate
import urlparse

from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.output_filter import MissingConfigError
from osxcollector.output_filters.output_filter import run_filter


class OpenDNSFilter(OutputFilter):
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
        super(OpenDNSFilter, self).__init__()

        self._api_key = self.get_config('api_key')
        self._blobs_with_domains = list()
        self._all_domains = set()
        self._threat_info_by_domain = dict()

    def filter_line(self, line):
        """Accumulate domains to categorize and lines to add categorized data to.

        Args:
            line: A string line of output

        Returns:
            A string or None
        """
        try:
            blob = simplejson.loads(line)
        except:
            return line      

        if 'osxcollector_domains' in blob:
            for domain in blob['osxcollector_domains']:
                self._all_domains.add(domain)
            self._blobs_with_domains.append(blob)
            return None
        else:
            return line

    def end_of_lines(self):
        """Caches the OpenDNS info for a set of domains

        Returns:
            An array of strings
        """
        self._lookup_domains()
        self._add_opendns_info_to_blobs()
        return ['{0}\n'.format(simplejson.dumps(blob)) for blob in self._blobs_with_domains]


    def _lookup_domains(self):
        """Caches the OpenDNS info for a set of domains"""
        opendns = investigate.Investigate(self._api_key)
        categorized = opendns.categorization(list(self._all_domains), labels=True)

        for domain in categorized.keys():
            if self._is_suspicious(categorized[domain]):
                self._threat_info_by_domain[domain] = {
                    'categorization': categorized[domain],
                    'security': opendns.security(domain)
                }

    def _add_opendns_info_to_blobs(self):
        """Adds osxcollector_opendns key to blobs"""
        for blob in self._blobs_with_domains:
            for domain in blob['osxcollector_domains']:
                opendns_info = self._threat_info_by_domain.get(domain)
                if opendns_info:
                    blob.setdefault('osxcollector_opendns', [])
                    blob['osxcollector_opendns'].append(opendns_info)

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
