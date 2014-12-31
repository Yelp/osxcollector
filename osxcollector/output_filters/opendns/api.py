# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
import sys

import simplejson
from osxcollector.output_filters.util.api_cache import ApiCache
from osxcollector.output_filters.util.error_messages import write_error_message
from osxcollector.output_filters.util.error_messages import write_exception
from osxcollector.output_filters.util.http import MultiRequest


class InvestigateApi(object):

    """Calls the OpenDNS investigate API.

    Applies rate limits and issues parallel requests.
    """

    BASE_URL = 'https://investigate.api.opendns.com/'

    def __init__(self, api_key, cache_file_name=None):
        auth_header = {'Authorization': 'Bearer {0}'.format(api_key)}
        self._requests = MultiRequest(default_headers=auth_header, max_requests=12, rate_limit=30)

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name) if cache_file_name else None

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
        all_responses = {}

        if self._cache:
            api_name = 'opendns-categorization'
            all_responses = self._cache.bulk_lookup(api_name, domains)
            domains = [key for key in domains if key not in all_responses.keys()]

        if len(domains):
            sys.stderr.write('[DOMAIN COUNT] {0}\n'.format(len(domains)))
            response = self._requests.multi_post(self._to_url(url_path), data=simplejson.dumps(domains))
            response = response[0]

            # TODO: Some better more expressive exception
            if not response:
                raise Exception('dang')

            for domain in response.keys():
                if self._cache:
                    self._cache.cache_value(api_name, domain, response[domain])
                all_responses[domain] = response[domain]

        return all_responses

    @MultiRequest.error_handling
    def security(self, domains):
        """Calls security end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of strings
        Returns:
            A dict of {domain: security_result}
        """
        fmt_url_path = 'security/name/{0}.json'
        all_responses = {}

        if self._cache:
            api_name = 'opendns-security'
            all_responses = self._cache.bulk_lookup(api_name, domains)
            domains = [key for key in domains if key not in all_responses.keys()]

        if len(domains):
            urls = self._to_urls(fmt_url_path, domains)
            responses = self._requests.multi_get(urls)
            responses = dict(zip(domains, responses))
            for domain in responses.keys():
                if self._cache:
                    self._cache.cache_value(api_name, domain, responses[domain])
                all_responses[domain] = responses[domain]

        return all_responses

    @MultiRequest.error_handling
    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of string domain names
        """
        fmt_url_path = 'recommendations/name/{0}.json'
        all_responses = {}

        if self._cache:
            api_name = 'opendns-cooccurrences'
            all_responses = self._cache.bulk_lookup(api_name, domains)
            domains = [key for key in domains if key not in all_responses.keys()]

        if len(domains):
            urls = self._to_urls(fmt_url_path, domains)
            responses = self._requests.multi_get(urls)
            responses = dict(zip(domains, responses))
            for domain in responses.keys():
                if self._cache:
                    self._cache.cache_value(api_name, domain, responses[domain])
                all_responses[domain] = responses[domain]

        return all_responses

    @MultiRequest.error_handling
    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: an enumerable of strings as ips
        Returns:
            An enumerable of string domain names
        """
        fmt_url_path = 'dnsdb/ip/a/{0}.json'
        all_responses = {}

        if self._cache:
            api_name = 'opendns-rr_history'
            all_responses = self._cache.bulk_lookup(api_name, ips)
            ips = [key for key in ips if key not in all_responses.keys()]

        if len(ips):
            urls = self._to_urls(fmt_url_path, ips)
            responses = self._requests.multi_get(urls)
            responses = dict(zip(ips, responses))
            for ip in responses.keys():
                if self._cache:
                    self._cache.cache_value(api_name, ip, responses[ip])
                all_responses[ip] = responses[ip]

        return all_responses

        # for response in responses:
        #     for rr_domain in response.get('rrs', []):
        #         for elem in expand_domain(rr_domain['rr']):
        #             rr_domains.add(elem)

        # return rr_domains
