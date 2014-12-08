# -*- coding: utf-8 -*-
#
# VirusTotalApi makes calls to the VirusTotal API.
# It uses the grequests library to make many calls in parrallel.
#
import grequests


class VirusTotalApi(object):
    BASE_DOMAIN = 'http://www.virustotal.com/vtapi/v2/'

    def __init__(self, api_key):
        self._api_key = api_key

    def _make_requests(self, endpoint_url, params):
        MAX_SIMULTANEOUS_REQUESTS = 64

        responses = []
        chunks = [params[pos:pos + MAX_SIMULTANEOUS_REQUESTS] for pos in xrange(0, len(params), MAX_SIMULTANEOUS_REQUESTS)]
        for chunk in chunks:
            requests = [grequests.get(endpoint_url, params=param) for param in chunk]
            responses.extend(grequests.map(requests))

        return [response.json() for response in responses]

    def get_domain_reports(self, domains):
        params = [{"domain": domain, 'apikey': self._api_key} for domain in domains]
        responses = self._make_requests(self.BASE_DOMAIN + 'domain/report', params)
        return dict([(domain, response) for domain, response in zip(domains, responses)])
