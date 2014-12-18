# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
# It uses the grequests library to make many calls in parrallel.
#
import sys
from traceback import extract_tb

import grequests


def _exception_handler(request, exception):
    exc_type, _, exc_traceback = sys.exc_info()
    sys.stderr.write('[ERROR] {0} {1}\n'.format(exc_type, extract_tb(exc_traceback)))


class VirusTotalApi(object):
    BASE_DOMAIN = 'http://www.virustotal.com/vtapi/v2/'
    REQ_TIMEOUT = 25.0
    MAX_SIMULTANEOUS_REQUESTS = 10

    def __init__(self, api_key):
        self._api_key = api_key

    def _get_request(self, endpoint_url, param):
        return grequests.get(endpoint_url, params=param, timeout=self.REQ_TIMEOUT)

    def _make_requests(self, endpoint_url, params):

        all_responses = []
        chunk_size = self.MAX_SIMULTANEOUS_REQUESTS
        chunks = [params[pos:pos + chunk_size] for pos in xrange(0, len(params), chunk_size)]
        for chunk in chunks:
            get_requests = [self._get_request(endpoint_url, param) for param in chunk]
            for get_response in grequests.map(get_requests):
                if not get_response:
                    continue
                if 200 == get_response.status_code:
                    all_responses.append(get_response.json())
                else:
                    sys.stderr.write('REQUESTS FAILED {0}\n'.format(get_response.status_code))
                    all_responses.append({})

        return all_responses

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
        responses = self._make_requests(self.BASE_DOMAIN + 'file/report', params)
        return dict([(resource, response) for resource, response in zip(resources, responses)])

    def get_domain_reports(self, domains):
        params = [{"domain": domain, 'apikey': self._api_key} for domain in domains]
        responses = self._make_requests(self.BASE_DOMAIN + 'domain/report', params)
        return dict([(domain, response) for domain, response in zip(domains, responses)])
