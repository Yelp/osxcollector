# -*- coding: utf-8 -*-
#
# ShadowServerApi makes calls to the ShadowServer APIs.
#
import simplejson

from osxcollector.output_filters.util.api_cache import ApiCache
from osxcollector.output_filters.util.http import MultiRequest


class ShadowServerApi(object):
    BINTEST_URL = u'http://bin-test.shadowserver.org/api'

    def __init__(self, cache_file_name=None):
        """Establishes basic HTTP params and loads a cache.

        Args:
            cache_file_name: String file name of cache.
        """

        # TODO - lookup request rate limit
        # By observation, ShadowServer can be quite slow, so give it 90 seconds before it times out.
        self._requests = MultiRequest(max_requests=2, req_timeout=90.0)

        # Create an ApiCache if instructed to
        self._cache = ApiCache(cache_file_name) if cache_file_name else None

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
        all_responses = {}

        if self._cache:
            api_name = 'shadowserver-bin-test'
            all_responses = self._cache.bulk_lookup(api_name, hashes)
            hashes = [key for key in hashes if key not in all_responses.keys()]
            all_responses = {key: val for key, val in all_responses.iteritems() if len(val) >= 2}

        HASHES_PER_REQ = 25
        hash_chunks = ['\n'.join(hashes[pos:pos + HASHES_PER_REQ]) for pos in xrange(0, len(hashes), HASHES_PER_REQ)]

        responses = self._requests.multi_post(self.BINTEST_URL, data=hash_chunks, to_json=False, send_as_file=True)
        for response in responses:
            if 200 == response.status_code:
                response_lines = response.text.split('\n')
                for line in response_lines:
                    # Set an initial val.
                    val = {}

                    # There is just a key, no value. This means the hash was unknown to ShadowServer.
                    index_of_first_space = line.find(' ')
                    if -1 == index_of_first_space:
                        index_of_first_space = len(line)
                    key = line[:index_of_first_space].lower()

                    # The response only has a JSON body if the hash was known.
                    json_text = line[index_of_first_space + 1:]
                    if len(json_text):
                        try:
                            val = simplejson.loads(json_text)
                            # A very short response indicates an error?
                            if len(val.keys()) >= 2:
                                all_responses[key] = val

                        except ValueError:
                            # Sometimes ShadowServer returns invalid data. Silently skip it.
                            pass

                    if self._cache:
                        self._cache.cache_value(api_name, key, val)

        return all_responses
