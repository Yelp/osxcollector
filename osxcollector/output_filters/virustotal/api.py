# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
#
from osxcollector.output_filters.util.api_cache import ApiCache
from osxcollector.output_filters.util.config import config_get_deep
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
        api_name = 'virustotal-file-reports'
        (all_responses, resources) = self._bulk_cache_lookup(api_name, resources)

        resource_chunks = self._prepare_resource_chunks(resources)
        response_chunks = self._request_reports("resource", resource_chunks, 'file/report')

        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    @MultiRequest.error_handling
    def get_domain_reports(self, domains):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            domains: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        api_name = 'virustotal-domain-reports'
        (all_responses, domains) = self._bulk_cache_lookup(api_name, domains)

        responses = self._request_reports("domain", domains, 'domain/report')

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
        Returns:
            A dict with the URL as key and the VT report as value.
        """
        api_name = 'virustotal-url-reports'
        (all_responses, resources) = self._bulk_cache_lookup(api_name, resources)

        resource_chunks = self._prepare_resource_chunks(resources, '\n')
        response_chunks = self._request_reports("resource", resource_chunks, 'url/report')

        self._extract_response_chunks(all_responses, response_chunks, api_name)

        return all_responses

    def _bulk_cache_lookup(self, api_name, keys):
        """Performes a bulk cache lookup and returns a tuple with the results
        found and the keys missing in the cache. If cached is not configured
        it will return an empty dictionary of found results and the initial
        list of keys.

        Args:
            api_name: a string name of the API.
            keys: an enumerable of string keys.
        Returns:
            A tuple: (responses found, missing keys).
        """
        if self._cache:
            responses = self._cache.bulk_lookup(api_name, keys)
            missing_keys = [key for key in keys if key not in responses.keys()]
            return (responses, missing_keys)

        return ({}, keys)

    def _prepare_resource_chunks(self, resources, resource_delim=','):
        """As in some VirusTotal API methods the call can be made for multiple
        resources at once this method prepares a list of concatenated resources
        according to the maximum number of resources per requests.

        Args:
            resources: a list of the resources.
            resource_delim: a string used to separate the resources.
              Default value is a comma.
        Returns:
            A list of the concatenated resources.
        """
        resources_per_req = config_get_deep('virustotal.resources_per_req', 25)
        return [resource_delim.join(resources[pos:pos + resources_per_req]) for pos in xrange(0, len(resources), resources_per_req)]

    def _request_reports(self, resource_param_name, resources, endpoint_name):
        """Sends multiples requests for the resources to a particular endpoint.

        Args:
            resource_param_name: a string name of the resource parameter.
            resources: list of of the resources.
            endpoint_name: VirusTotal endpoint URL suffix.
        Returns:
            A list of the responses.
        """
        params = [{resource_param_name: resource, 'apikey': self._api_key} for resource in resources]
        return self._requests.multi_get(self.BASE_DOMAIN + endpoint_name, query_params=params)

    def _extract_response_chunks(self, all_responses, response_chunks, api_name):
        """Extracts and caches the responses from the response chunks in case
        of the responses for the requests containing multiple concatenated
        resources. Extracted responses are added to the already cached
        responses passed in the all_responses parameter.

        Args:
            all_responses: a list containing already cached responses.
            response_chunks: a list with response chunks.
            api_name: a string name of the API.
        """
        for response_chunk in response_chunks:
            if not isinstance(response_chunk, list):
                response_chunk = [response_chunk]
            for response in response_chunk:
                if not response:
                    continue

                if self._cache:
                    self._cache.cache_value(api_name, response['resource'], response)
                all_responses[response['resource']] = response
