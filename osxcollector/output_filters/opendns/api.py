# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
# TODO: Replace investigate module with custom calls to OpenDNS and parrallelize with grequests.
#
import sys
import time
from collections import namedtuple
from traceback import extract_tb

import grequests
import simplejson
from osxcollector.output_filters.find_domains import expand_domain


def investigate_error_handling(fn):
    """Handle errors that might arrise while calling out to OpenDNS."""
    def wrapper(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
            return result
        except Exception as e:
            de_args = repr([a for a in args]) or ''
            de_kwargs = repr([(a, kwargs[a]) for a in kwargs]) or ''
            sys.stderr.write('[ERROR] calling {0} {1} {2}\n'.format(fn.__name__, de_args, de_kwargs))

            exc_type, _, exc_traceback = sys.exc_info()
            sys.stderr.write('[ERROR] {0} {1}\n'.format(exc_type, extract_tb(exc_traceback)))

            if hasattr(e, 'response'):
                sys.stderr.write('[ERROR] request {0}\n'.format(repr(e.response)))
            if hasattr(e, 'request'):
                sys.stderr.write('[ERROR] request {0}\n'.format(repr(e.request)))

            raise e
    return wrapper

CallRecord = namedtuple('CallRecord', ['time', 'num_calls'])


class RateLimiter(object):

    """Limits how many calls can be made per second"""

    def __init__(self, calls_per_sec):
        self._max_calls_per_second = calls_per_sec
        self._call_times = []
        self._outstanding_calls = 0

    def make_calls(self, num_calls=1):
        """Adds appropriate sleep to avoid making too many calls.

        Args:
            num_calls: int the number of calls which will be made
        """
        self._cull()
        while self._outstanding_calls + num_calls > self._max_calls_per_second:
            time.sleep(0.5)
            self._cull()

        self._call_times.append(CallRecord(time=time.time(), num_calls=num_calls))
        self._outstanding_calls += num_calls

    def _cull(self):
        """Remove calls more than 1 minutes old from the queue."""
        right_now = time.time()

        cull_from = -1
        for index in xrange(len(self._call_times)):
            if right_now - self._call_times[index].time >= 1.0:
                cull_from = index
                self._outstanding_calls -= self._call_times[index].num_calls
            else:
                break

        if cull_from > -1:
            self._call_times = self._call_times[cull_from + 1:]


class InvestigateApi(object):

    """Calls the OpenDNS investigate API"""

    BASE_URL = 'https://investigate.api.opendns.com/'
    MAX_SIMULTANEOUS_REQUESTS = 10

    def __init__(self, api_key):
        self._auth_header = {'Authorization': 'Bearer {0}'.format(api_key)}
        self._rate_limiter = RateLimiter(calls_per_sec=10)

    def _make_post_requests(self, path, data=None):
        post_request = grequests.post(self.BASE_URL + path, data=data, headers=self._auth_header)
        response = grequests.map([post_request])
        return response[0].json()

    def _make_get_requests(self, path_fmt_string, params):
        all_responses = []
        all_urls = [self.BASE_URL + path_fmt_string.format(param.encode('utf-8', errors='ignore')) for param in params]

        chunk_size = self.MAX_SIMULTANEOUS_REQUESTS  # self._rate_limiter.calls_per_sec
        url_chunks = [all_urls[pos:pos + chunk_size] for pos in xrange(0, len(all_urls), chunk_size)]
        for chunk in url_chunks:
            self._rate_limiter.make_calls(num_calls=len(chunk))
            get_requests = [grequests.get(req_url, headers=self._auth_header) for req_url in chunk]
            for response in grequests.map(get_requests):
                if 200 == response.status_code:
                    all_responses.append(response.json())
                else:
                    sys.stderr.write('REQUESTS FAILED {0}\n'.format(response.status_code))
                    all_responses.append({})

        return all_responses

    @investigate_error_handling
    def categorization(self, domains):
        """Calls categorization end point and adds an 'is_suspicious' key to each response.

        Args:
            domains - A list of domains
        Returns:
            A dict of {domain: categorization_result}
        """
        path = 'domains/categorization/?showLabels'
        response = self._make_post_requests(path, data=simplejson.dumps(domains))
        for domain in response.keys():
            response[domain]['is_suspicious'] = self._is_categorization_suspicious(response[domain])
        return response

    @investigate_error_handling
    def security(self, domains):
        """Calls security end point and adds an 'is_suspicious' key to each response.

        Args:
            domains - A list of strings
        Returns:
            A dict of results from the security_info call
        """
        fmt_string = 'security/name/{0}.json'
        responses = self._make_get_requests(fmt_string, domains)
        responses = dict(zip(domains, responses))
        for domain in responses.keys():
            response = self._trim_security_result(responses[domain])
            response['is_suspicious'] = self._is_security_suspicious(response)
            responses[domain] = response

        return responses

    @investigate_error_handling
    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: a list of strings as domain names
        Returns:
            A set of domains
        """
        cooccur_domains = set()

        fmt_string = 'recommendations/name/{0}.json'
        responses = self._make_get_requests(fmt_string, domains)
        for response in responses:
            for occur_domain in response.get('pfs2', []):
                for elem in expand_domain(occur_domain[0]):
                    cooccur_domains.add(elem)

        return cooccur_domains

    @investigate_error_handling
    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: a list of strings as ips
        Returns:
            A set of domains
        """
        rr_domains = set()

        fmt_string = 'dnsdb/ip/a/{0}.json'
        responses = self._make_get_requests(fmt_string, ips)
        for response in responses:
            for rr_domain in response.get('rrs', []):
                for elem in expand_domain(rr_domain['rr']):
                    rr_domains.add(elem)

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

        result['found'] = security_info.get('found', False)

        return result

    def _is_security_suspicious(self, security_info):
        """Analyzes info from opendns and makes a boolean determination of suspicious or not.

        Either looks for low values for a specific set of properties, looks for known participation in
        a threat campaign, or looks for unknown domains.

        Args:
            security_info - The result of a call to the security endpoint
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
