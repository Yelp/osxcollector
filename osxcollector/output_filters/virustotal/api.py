# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
# It uses the grequests library to make many calls in parrallel.
#
from osxcollector.output_filters.base_filters.threat_feed import MultiRequest


class VirusTotalApi(object):
    BASE_DOMAIN = 'https://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key):
        self._api_key = api_key
        self._requests = MultiRequest()

    @MultiRequest.error_handling
    def get_file_reports(self, resources):
        """Retrieves the most recent report on a given sample (md5/sha1/sha256 hash).

        Args:
            resources: list of md5/sha1/sha256 hashes.
            Each list element can be also a CSV list made up of a combination of hashes
            (up to 4 items with the standard request rate), this allows to perform
            a batch request with one single call.
        Returns:
            dict
        """
        params = [{"resource": resource, 'apikey': self._api_key} for resource in resources]
        responses = self._requests.multi_get_params(self.BASE_DOMAIN + 'file/report', params)
        return dict(zip(resources, responses))

    @MultiRequest.error_handling
    def get_domain_reports(self, domains):
        params = [{"domain": domain, 'apikey': self._api_key} for domain in domains]
        responses = self._requests.multi_get_params(self.BASE_DOMAIN + 'domain/report', params)
        return dict(zip(domains, responses))
