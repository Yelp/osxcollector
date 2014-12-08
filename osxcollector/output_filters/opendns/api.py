# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
# TODO: Replace investigate module with custom calls to OpenDNS and parrallelize with grequests.
#
import sys
from collections import namedtuple

import investigate
import requests
import requests.exceptions
from osxcollector.output_filters.find_domains import clean_domain
from osxcollector.output_filters.find_domains import expand_domain


def investigate_error_handling(fn):
    """Handle errors that might arrise while calling out to OpenDNS."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            de_args = repr([a for a in args]) or ''
            de_kwargs = repr([(a, kwargs[a]) for a in kwargs]) or ''
            sys.stderr.write('[ERROR calling {0} {1} {2}\n'.format(fn.__name__, de_args, de_kwargs))

            if hasattr(e, 'response'):
                sys.stderr.write('[ERROR request {0}\n'.format(repr(e.response)))
            if hasattr(e, 'request'):
                sys.stderr.write('[ERROR request {0}\n'.format(repr(e.request)))

            raise e
    return wrapper


class InvestigateApi(object):

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
            result[domain]['is_suspicious'] = self._is_categorization_suspicious(result[domain])
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
                for domain in expand_domain(occur[0]):
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
                for domain in expand_domain(record['rr']):
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
