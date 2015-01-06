# -*- coding: utf-8 -*-
#
# InvestigateApi makes calls to the OpenDNS Investigate API.
#
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
    def _multi_get(self, cache_api_name, fmt_url_path, url_params):
        """Makes multiple GETs to an OpenDNS endpoint.

        Args:
            cache_api_name: string api_name for caching
            fmt_url_path: format string for building URL paths
            url_params: An enumerable of strings used in building URLs
        Returns:
            A dict of {url_param: api_result}
        """
        all_responses = {}

        if self._cache:
            all_responses = self._cache.bulk_lookup(cache_api_name, url_params)
            url_params = [key for key in url_params if key not in all_responses.keys()]

        if len(url_params):
            urls = self._to_urls(fmt_url_path, url_params)
            responses = self._requests.multi_get(urls)
            responses = dict(zip(url_params, responses))
            for url_param in responses.keys():
                if self._cache:
                    self._cache.cache_value(cache_api_name, url_param, responses[url_param])
                all_responses[url_param] = responses[url_param]

        return all_responses

    def security(self, domains):
        """Calls security end point and adds an 'is_suspicious' key to each response.

        Args:
            domains: An enumerable of strings
        Returns:
            A dict of {domain: security_result}
        """
        api_name = 'opendns-security'
        fmt_url_path = 'security/name/{0}.json'
        return self._multi_get(api_name, fmt_url_path, domains)

    def cooccurrences(self, domains):
        """Get the domains related to input domains.

        Args:
            domains: an enumerable of strings domain names
        Returns:
            An enumerable of string domain names
        """
        api_name = 'opendns-cooccurrences'
        fmt_url_path = 'recommendations/name/{0}.json'
        return self._multi_get(api_name, fmt_url_path, domains)

    def rr_history(self, ips):
        """Get the domains related to input ips.

        Args:
            ips: an enumerable of strings as ips
        Returns:
            An enumerable of string domain names
        """
        api_name = 'opendns-rr_history'
        fmt_url_path = 'dnsdb/ip/a/{0}.json'
        return self._multi_get(api_name, fmt_url_path, ips)
