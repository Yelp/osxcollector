# -*- coding: utf-8 -*-
from contextlib import nested

import testify as T
from mock import patch
from osxcollector.output_filters.find_blacklisted import FindBlacklistedFilter
from tests.output_filters.base_filters.output_filter_test import RunFilterTest


class FindBlacklistedFilterTest(RunFilterTest):

    @T.setup
    def setup_configs(self):
        self._hash_config = {
            'blacklist_name': 'hashes',
            'blacklist_keys': ['md5', 'sha1', 'sha2'],
            'blacklist_file_path': '/tmp/hashes_blacklist.txt',
            'blacklist_is_regex': False
        }
        self._hash_file_contents = {
            'ffff5f60462c38b1d235cb3509876543',
            'ffff234d2a50a42a87389f1234561a21',
            'ffff51e77b442ee23188d87e4abcdef0'
        }

        self._domain_config = {
            'blacklist_name': 'domains',
            'blacklist_keys': ['osxcollector_domains'],
            'blacklist_file_path': '/var/domain_blacklist.txt',
            'blacklist_is_domains': True,
            'blacklist_is_regex': True
        }
        self._domain_file_contents = {
            'yelp.com',
            'github.com',
            'example.com'
        }

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
        self._test_blacklisted(input_blobs, expected_blacklists, self._hash_config, self._hash_file_contents)

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
        self._test_blacklisted(input_blobs, expected_blacklists, self._hash_config, self._hash_file_contents)

    def test_simple_domains(self):
        input_blobs = [
            {'osxcollector_domains': ['biz.yelp.com']},
            {'osxcollector_domains': ['yelp.github.com']},
            {'osxcollector_domains': ['example.com']}
        ]
        expected_blacklists = [
            {'domains': ['yelp.com']},
            {'domains': ['github.com']},
            {'domains': ['example.com']},
        ]
        self._test_blacklisted(input_blobs, expected_blacklists, self._domain_config, self._domain_file_contents)

    def _test_blacklisted(self, input_blobs, expected_blacklists, blacklist_config, blacklist_file_contents):

        with nested(
            patch('osxcollector.output_filters.base_filters.output_filter.Config.get_config', return_value=[blacklist_config]),
            patch('osxcollector.output_filters.util.blacklist.Blacklist._read_blacklist_file_contents',
                  return_value=blacklist_file_contents)
        ):
            output_filter = FindBlacklistedFilter()
            output_blobs = self._run_filter(output_filter, input_blobs)

        actual_blacklists = list(blob.get('osxcollector_blacklist', None) for blob in output_blobs)
        for actual, expected in zip(actual_blacklists, expected_blacklists):
            # actual = sorted(actual) if actual else actual
            # expected = sorted(expected) if expected else expected
            T.assert_equal(actual, expected)

        # Minus 'osxcollector_blacklist' key, the input should be unchanged
        for input_blob, output_blob in zip(input_blobs, output_blobs):
            if 'osxcollector_blacklist' in output_blob:
                del output_blob['osxcollector_blacklist']
            T.assert_equal(input_blob, output_blob)
