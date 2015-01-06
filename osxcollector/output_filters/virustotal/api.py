# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
#
from osxcollector.output_filters.util.api_cache import ApiCache
from osxcollector.output_filters.util.http import MultiRequest


class VirusTotalApi(object):
    BASE_DOMAIN = 'https://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key, cache_file_name=None):
        """Establishes basic HTTP params and loads a cache.

        Args:
            api_key: VirusTotal API key
            cache_file_name: String file name of cache.
        """
        self._api_key = api_key
        self._requests = MultiRequest()

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name) if cache_file_name else None

    @MultiRequest.error_handling
    def get_file_reports(self, resources):
        """Retrieves the most recent reports for a set of md5, sha1, and/or sha2 hashes.

        Args:
            resources: list of string hashes.
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        all_responses = {}
        if self._cache:
            api_name = 'virustotal-file-reports'
            all_responses = self._cache.bulk_lookup(api_name, resources)
            resources = [key for key in resources if key not in all_responses.keys()]

        RESOURCES_PER_REQ = 25
        resource_chunks = [','.join(resources[pos:pos + RESOURCES_PER_REQ]) for pos in xrange(0, len(resources), RESOURCES_PER_REQ)]

        params = [{"resource": resource_chunk, 'apikey': self._api_key} for resource_chunk in resource_chunks]
        responses = self._requests.multi_get(self.BASE_DOMAIN + 'file/report', query_params=params)
        for response_chunk in responses:
            if not isinstance(response_chunk, list):
                response_chunk = [response_chunk]
            for response in response_chunk:
                if not response:
                    continue

                if self._cache:
                    self._cache.cache_value(api_name, response['resource'], response)
                all_responses[response['resource']] = response

        return all_responses

    @MultiRequest.error_handling
    def get_domain_reports(self, domains):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            domains: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        all_responses = {}
        if self._cache:
            api_name = 'virustotal-domain-reports'
            all_responses = self._cache.bulk_lookup(api_name, domains)
            domains = [key for key in domains if key not in all_responses.keys()]

        params = [{"domain": domain, 'apikey': self._api_key} for domain in domains]
        responses = self._requests.multi_get(self.BASE_DOMAIN + 'domain/report', query_params=params)

        for domain, response in zip(domains, responses):
            if self._cache:
                self._cache.cache_value(api_name, domain, response)
            all_responses[domain] = response

        return all_responses

    @MultiRequest.error_handling
    def get_url_reports(self, resources):
        """Retrieves a scan report on a given URL.

        Args:
            resources: list of URLs.
            Each list element can be also a CSV list made up of a combination of hashes
            and scan_ids so as to perform a batch request with one single call
            (up to 4 resources per call with the standard request rate).
            When sending multiples, the scan_ids or URLs must be separated by a new line character.
        Returns:
            dict
        """
        params = [{"resource": resource, 'apikey': self._api_key} for resource in resources]
        responses = self._requests.multi_get(self.BASE_DOMAIN + 'url/report', params)
        return dict([(resource, response) for resource, response in zip(resources, responses)])
