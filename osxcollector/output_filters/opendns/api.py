# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
from collections import namedtuple

import simplejson
from osxcollector.output_filters.util.domains import expand_domain
from osxcollector.output_filters.util.error_messages import write_error_message
from osxcollector.output_filters.util.error_messages import write_exception
from osxcollector.output_filters.util.http import MultiRequest


class InvestigateApi(object):

    """Calls the OpenDNS investigate API.

    Applies rate limits and issues parallel requests.
    """

    BASE_URL = 'https://investigate.api.opendns.com/'

    def __init__(self, api_key):
        auth_header = {'Authorization': 'Bearer {0}'.format(api_key)}
        self._requests = MultiRequest(default_headers=auth_header, max_requests=12, rate_limit=30)

    @classmethod
    def _to_url(cls, url_path):
        try:
            return u'{0}{1}'.format(cls.BASE_URL, url_path)
        except Exception as e:
            write_error_message(url_path)
            write_exception(e)
            raise e

    @classmethod
    def _to_urls(cls, fmt_url_path, url_path_args):
        url_paths = []
        for path_arg in url_path_args:
            try:
                url_paths.append(fmt_url_path.format(path_arg))
            except Exception as e:
                write_error_message(path_arg)
                write_exception(e)
                raise e

        return [cls._to_url(url_path) for url_path in url_paths]

    @MultiRequest.error_handling
    def categorization(self, domains):
        """Calls categorization end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of domains
        Returns:
            A dict of {domain: categorization_result}
        """
        url_path = 'domains/categorization/?showLabels'
        response = self._requests.multi_post(self._to_url(url_path), data=simplejson.dumps(domains))
        response = response[0]

        # TODO: Some better more expressive exception
        if not response:
            raise Exception('dang')

        for domain in response.keys():
            response[domain]['is_suspicious'] = self._is_categorization_suspicious(response[domain])
        return response

    @MultiRequest.error_handling
    def security(self, domains):
        """Calls security end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of strings
        Returns:
            A dict of {domain: security_result}
        """
        fmt_url_path = 'security/name/{0}.json'

        urls = self._to_urls(fmt_url_path, domains)
        responses = self._requests.multi_get(urls)
        responses = dict(zip(domains, responses))
        for domain in responses.keys():
            response = self._trim_security_result(responses[domain])
            response['is_suspicious'] = self._is_security_suspicious(response)
            responses[domain] = response

        return responses

    @MultiRequest.error_handling
    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of string domain names
        """
        fmt_url_path = 'recommendations/name/{0}.json'
        urls = self._to_urls(fmt_url_path, domains)

        cooccur_domains = set()
        responses = self._requests.multi_get(urls)
        for response in responses:
            for occur_domain in response.get('pfs2', []):
                for elem in expand_domain(occur_domain[0]):
                    cooccur_domains.add(elem)

        return cooccur_domains

    @MultiRequest.error_handling
    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: an enumerable of strings as ips
        Returns:
            An enumerable of string domain names
        """
        fmt_url_path = 'dnsdb/ip/a/{0}.json'
        urls = self._to_urls(fmt_url_path, ips)

        rr_domains = set()
        responses = self._requests.multi_get(urls)
        for response in responses:
            for rr_domain in response.get('rrs', []):
                for elem in expand_domain(rr_domain['rr']):
                    rr_domains.add(elem)

        return rr_domains

    def _is_categorization_suspicious(self, category_info):
        """Analyzes info from OpenDNS and makes a boolean determination of suspicious or not.

        Args:
            category_info: The result of a call to the categorization endpoint.
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
        """Converts the results of a security call into a smaller dict.

        Args:
            security_info: The result of a call to the security endpoint.
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

        result['found'] = security_info.get('found', False)

        return result

    def _is_security_suspicious(self, security_info):
        """Analyzes info from OpenDNS and makes a boolean determination of suspicious or not.

        Either looks for low values for a specific set of properties, looks for known participation in
        a threat campaign, or looks for unknown domains.

        Args:
            security_info: The result of a call to the security endpoint
        Returns:
            boolean
        """
        # Categorization of site
        if any([security_info.get(key, None) for key in self.SECURITY_BAD_KEYS]):
            return True

        for security_check in self.SECURITY_CHECKS:
            if security_info.get(security_check.key, security_check.max) <= security_check.threshold:
                return True

        if not security_info.get('found', False):
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
        SecurityCheck('dga_score', -100, 0, -70),

        # Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain.
        # Securerank is designed to identify hostnames requested by known infected clients but never requested
        # by clean clients, assuming these domains are more likely to be bad.
        # Scores returned range from -100 (suspicious) to 100 (benign).
        # <http://labs.opendns.com/2013/03/28/secure-rank-a-large-scale-discovery-algorithm-for-predictive-detection/>
        SecurityCheck('securerank2', -100, 100, -10),

        # ASN reputation score, ranges from -100 to 0 with -100 being very suspicious
        SecurityCheck('asn_score', -100, 0, -3),

        # Prefix ranks domains given their IP prefixes (An IP prefix is the first three octets in an IP address)
        # and the reputation score of these prefixes.
        # Ranges from -100 to 0, -100 being very suspicious
        SecurityCheck('prefix_score', -100, 0, -12),

        # RIP ranks domains given their IP addresses and the reputation score of these IP addresses.
        # Ranges from -100 to 0, -100 being very suspicious
        SecurityCheck('rip_score', -100, 0, -25)
    ]

    SECURITY_BAD_KEYS = [
        # The name of any known attacks associated with this domain.
        # Returns blank is no known threat associated with domain.
        'attack',

        # The type of the known attack, such as botnet or APT.
        # Returns blank if no known threat associated with domain.
        'threat_type'
    ]
