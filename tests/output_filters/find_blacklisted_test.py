# -*- coding: utf-8 -*-
from osxcollector.output_filters.find_blacklisted import FindBlacklistedFilter
from tests.output_filters.run_filter_test import RunFilterTest


class FindBlacklistedFilterTest(RunFilterTest):

    def test_simple_hashes(self):
        input_blobs = [
            {'md5': 'ffff5f60462c38b1d235cb3509876543'},
            {'sha1': 'ffff234d2a50a42a87389f1234561a21'},
            {'sha2': 'ffff51e77b442ee23188d87e4abcdef0'}
        ]
        expected_blacklists = [
            {'hashes': ['ffff5f60462c38b1d235cb3509876543']},
            {'hashes': ['ffff234d2a50a42a87389f1234561a21']},
            {'hashes': ['ffff51e77b442ee23188d87e4abcdef0']}
        ]
        self._run_test(input_blobs, expected_blacklists)

    def test_no_hashes(self):
        input_blobs = [
            # Not the right key
            {'apple': 'ffff5f60462c38b1d235cb3509876543'},
            # Value not on blacklist
            {'sha1': 'aaaa234d2a50a42a87389f1234561a21'}
        ]
        expected_blacklists = [
            None,
            None
        ]
        self._run_test(input_blobs, expected_blacklists)

    def test_simple_domains(self):
        input_blobs = [
            {'osxcollector_domains': ['biz.example.com']},
            {'osxcollector_domains': ['www.example.co.uk']},
            {'osxcollector_domains': ['example.org']}
        ]
        expected_blacklists = [
            {'domains': ['example.com']},
            {'domains': ['example.co.uk']},
            {'domains': ['example.org']},
        ]
        self._run_test(input_blobs, expected_blacklists)

    def _run_test(self, input_blobs, expected_blacklists):

        output_blobs = self.run_test(FindBlacklistedFilter, input_blobs)

        # added_key, expected_values, input_blobs, output_blobs
        self.assert_key_added_to_blob('osxcollector_blacklist', expected_blacklists, input_blobs, output_blobs)
