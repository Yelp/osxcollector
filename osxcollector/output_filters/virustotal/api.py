# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
#
from osxcollector.output_filters.util.http import MultiRequest


class VirusTotalApi(object):
    BASE_DOMAIN = 'https://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key):
        self._api_key = api_key
        self._requests = MultiRequest(req_timeout=60.0)

    @MultiRequest.error_handling
    def get_file_reports(self, resources):
        """Retrieves the most recent reports for a set of md5, sha1, and/or sha2 hashes.

        Args:
            resources: list of string hashes.
        Returns:
            A dict with the hash as key and the VT report as value.
        """
        RESOURCES_PER_REQ = 25
        resource_chunks = [','.join(resources[pos:pos + RESOURCES_PER_REQ]) for pos in xrange(0, len(resources), RESOURCES_PER_REQ)]

        all_responses = {}

        params = [{"resource": resource_chunk, 'apikey': self._api_key} for resource_chunk in resource_chunks]
        responses = self._requests.multi_get(self.BASE_DOMAIN + 'file/report', query_params=params)
        for response_chunk in responses:
            if not isinstance(response_chunk, list):
                response_chunk = [response_chunk]
            for response in response_chunk:
                if response:
                    all_responses[response['resource']] = response

        return all_responses

    @MultiRequest.error_handling
    def get_domain_reports(self, domains):
        """Retrieves the most recent VT info for a set of domains.

        Args:
            resources: list of string domains.
        Returns:
            A dict with the domain as key and the VT report as value.
        """
        params = [{"domain": domain, 'apikey': self._api_key} for domain in domains]
        responses = self._requests.multi_get(self.BASE_DOMAIN + 'domain/report', query_params=params)
        return dict(zip(domains, responses))
