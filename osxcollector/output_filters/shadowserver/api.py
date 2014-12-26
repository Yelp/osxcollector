# -*- coding: utf-8 -*-
#
# ShadowServerApi makes calls to the ShadowServer APIs.
#
import simplejson
from osxcollector.output_filters.util.http import MultiRequest


class ShadowServerApi(object):
    BINTEST_URL = 'http://bin-test.shadowserver.org/api'

    def __init__(self):
        # TODO - lookup request rate limit
        # By observation, ShadowServer can be quite slow, so give it 90 seconds before it times out.
        self._requests = MultiRequest(max_requests=2, req_timeout=90.0)

    @MultiRequest.error_handling
    def get_bin_test(self, hashes):
        """Test hashes against a list of known software applications.

        Known hashes will return a dictionary of information.
        Unknown hashes will return nothing.

        Args:
            hashes: list of string hashes.
        Returns:
            A dict with the hash as key and the shadowserver report as value.
        """
        HASHES_PER_REQ = 25
        hash_chunks = ['\n'.join(hashes[pos:pos + HASHES_PER_REQ]) for pos in xrange(0, len(hashes), HASHES_PER_REQ)]

        all_responses = {}

        responses = self._requests.multi_post(self.BINTEST_URL, data=hash_chunks, to_json=False, send_as_file=True)
        for response in responses:
            if 200 == response.status_code:
                response_lines = response.text.split('\n')
                for line in response_lines:
                    index_of_first_space = line.find(' ')
                    if -1 == index_of_first_space:
                        continue
                    key = line[:index_of_first_space].lower()
                    json_text = line[index_of_first_space + 1:]
                    if not len(json_text):
                        continue

                    try:
                        val = simplejson.loads(json_text)
                    except ValueError:
                        # Sometimes ShadowServer returns invalid data
                        continue

                    if len(val.keys()) < 2:
                        continue

                    all_responses[key] = val
        return all_responses
