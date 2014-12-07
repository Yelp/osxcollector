#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# OpenDNSFilter uses OpenDNS to lookup the values in 'osxcollector_domains' and add 'osxcollector_opendns' key.
#
import sys
from collections import namedtuple

import investigate
import requests
import requests.exceptions
from osxcollector.output_filters.domains import clean_domain
from osxcollector.output_filters.domains import extract_domains
from osxcollector.output_filters.output_filter import run_filter
from osxcollector.output_filters.threat_feed import ThreatFeedFilter


class OpenDNSFilter(ThreatFeedFilter):

    """Uses OpenDNS to lookup the values in 'osxcollector_domains' and add 'osxcollector_opendns' key."""

    def __init__(self, only_lookup_when=None, is_suspicious_when=None):
        super(OpenDNSFilter, self).__init__('osxcollector_domains', 'osxcollector_opendns',
                                            only_lookup_when=only_lookup_when, is_suspicious_when=is_suspicious_when,
                                            api_key='opendns')

    def _lookup_iocs(self):
        """Caches the OpenDNS info for a set of domains"""
        investigate = Investigate(self._api_key)
        categorized = investigate.categorization(list(self._all_iocs))

        for domain in categorized.keys():
            categorized_info = categorized[domain]
            if self._should_get_security_info(domain, categorized_info):
                security = investigate.security(domain)
                if self._should_store_ioc_info(categorized_info, security):
                    self._threat_info_by_iocs[domain] = {
                        'domain': domain,
                        'categorization': categorized_info,
                        'security': security,
                        'link': 'https://investigate.opendns.com/domain-view/name/{0}/view'.format(domain)
                    }

    def _should_get_security_info(self, domain, categorized_info):
        """Figure out whether the info on the domain is interesting enough to gather more data."""
        if categorized_info['is_suspicious']:
            return True
        if 0 == categorized_info['status']:
            return True
        if domain in self._suspicious_iocs:
            return True
        return False

    def _should_store_ioc_info(self, categorized_info, security):
        """Figure out whether the data gathered is interesting enough to store in the output."""
        return categorized_info['is_suspicious'] or security['is_suspicious']


def investigate_error_handling(fn):
    """Handle errors that might arrise while calling out to OpenDNS."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except requests.exceptions.ConnectionError as e:
            de_args = repr([a for a in args]) or ''
            de_kwargs = repr([(a, kwargs[a]) for a in kwargs]) or ''
            sys.stderr.write('[ERROR calling {0} {1} {2}'.format(fn.__name__, de_args, de_kwargs))
            raise e
    return wrapper


class Investigate(object):

    """Wrap the OpenDNS investigate API"""

    def __init__(self, api_key):
        self._opendns = investigate.Investigate(api_key)

    @investigate_error_handling
    def categorization(self, domains):
        """Calls categorization end point and adds an 'is_suspicious' key to each result.

        Args:
            domains - A list of domains
        Returns:
            A dict of {domain: categorization_result}
        """
        result = self._opendns.categorization(domains, labels=True)
        for domain in result.keys():
            result[domain]['is_suspicious'] = self._is_categorization_suspicious(result, result[domain])
        return result

    @investigate_error_handling
    def security(self, domain):
        """Calls security end point and adds an 'is_suspicious' key to the result.

        Args:
            domain - A domain
        Returns:
            A dict of results from the security_info call
        """
        result = self._opendns.security(domain)
        result = self._trim_security_result(result)
        result['is_suspicious'] = self._is_security_suspicious(result)

        return result

    @investigate_error_handling
    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: a list of strings as domain names
        Returns:
            A set of domains
        """
        cooccur_domains = set()
        for domain in domains:
            cooccur = self._opendns.cooccurrences(domain)
            for occur in cooccur.get('pfs2', []):
                for domain in extract_domains(occur[0]):
                    cooccur_domains.add(clean_domain(domain))
        return cooccur_domains

    @investigate_error_handling
    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: a list of strings as domain names
        Returns:
            A set of domains
        """
        rr_domains = set()
        for ip in ips:
            history = self._opendns.rr_history(ip)
            for record in history.get('rrs', []):
                for domain in extract_domains(record['rr']):
                    rr_domains.add(domain)
        return rr_domains

    def _is_categorization_suspicious(self, category_info):
        """Analyzes info from opendns and makes a boolean determination of suspicious or not.

        Args:
            category_info: The result of a call to opendns.categorization
        Returns:
            boolean
        """
        if -1 == category_info['status']:
            return True
        elif any([cat in self.SUSPICIOUS_CATEGORIES for cat in category_info['content_categories']]):
            return True
        elif any([cat in self.SUSPICIOUS_CATEGORIES for cat in category_info['security_categories']]):
            return True

        return False

    def _trim_security_result(self, security_info):
        """Analyzes info from opendns and makes a boolean determination of suspicious or not.

        Args:
            security_info: The result of a call to opendns.categorization
        Returns:
            A dict
        """
        # dga_score sometimes has the wrong sign, fix that please
        dga_score = security_info.get('dga_score', 0)
        if dga_score > 0:
            security_info['dga_score'] = -1 * dga_score

        # There's a lot of info in the security_info, trim it
        result = {}
        for security_check in self.SECURITY_CHECKS:
            if security_check.key in security_info:
                result[security_check.key] = security_info[security_check.key]
        for key in self.SECURITY_BAD_KEYS:
            if key in security_info:
                result[key] = security_info[key]

        return result

    def _is_security_suspicious(self, security_info):
        """Analyzes info from opendns and makes a boolean determination of suspicious or not."""
        # Categorization of site
        if any([security_info.get(key, None) for key in self.SECURITY_BAD_KEYS]):
            return True

        for security_check in self.SECURITY_CHECKS:
            if security_info.get(security_check.key, security_check.max) <= security_check.threshold:
                return True

        return False

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

    SecurityCheck = namedtuple('SecurityCheck', ['key', 'min', 'max', 'threshold'])
    SECURITY_CHECKS = [
        # Domain Generation Algorithm. This score is generated based on the likeliness of the domain name being
        # generated by an algorithm rather than a human. This algorithm is designed to identify domains which have
        # been created using an automated randomization strategy, which is a common evasion technique in malware kits
        # or botnets. This score ranges from -100 (suspicious) to 0 (benign)
        # <http://labs.opendns.com/2013/10/24/mysterious-dga-lets-investigate-sgraph/>
        SecurityCheck('dga_score', -100, 0, -50),

        # Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain.
        # Securerank is designed to identify hostnames requested by known infected clients but never requested
        # by clean clients, assuming these domains are more likely to be bad.
        # Scores returned range from -100 (suspicious) to 100 (benign).
        # <http://labs.opendns.com/2013/03/28/secure-rank-a-large-scale-discovery-algorithm-for-predictive-detection/>
        SecurityCheck('securerank2', -100, 100, -10),

        # ASN reputation score, ranges from -100 to 0 with -100 being very suspicious
        SecurityCheck('asn_score', -100, 0, -50),

        # Prefix ranks domains given their IP prefixes (An IP prefix is the first three octets in an IP address)
        # and the reputation score of these prefixes.
        # Ranges from -100 to 0, -100 being very suspicious
        SecurityCheck('prefix_score', -100, 0, -50),

        # RIP ranks domains given their IP addresses and the reputation score of these IP addresses.
        # Ranges from -100 to 0, -100 being very suspicious
        SecurityCheck('rip_score', -100, 0, -50)
    ]

    SECURITY_BAD_KEYS = [
        # The name of any known attacks associated with this domain.
        # Returns blank is no known threat associated with domain.
        'attack',

        # The type of the known attack, such as botnet or APT.
        # Returns blank if no known threat associated with domain.
        'threat_type'
    ]


def main():
    run_filter(OpenDNSFilter())


if __name__ == "__main__":
    main()
