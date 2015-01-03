# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.find_blacklisted import FindBlacklistedFilter
from tests.output_filters.run_filter_test import assert_key_added_to_blob
from tests.output_filters.run_filter_test import run_filter_test


class FindBlacklistedFilterTest(T.TestCase):

    @T.setup
    def setup_configs(self):
        self._hash_config = {
            'blacklists': [
                {
                    'blacklist_name': 'hashes',
                    'blacklist_keys': ['md5', 'sha1', 'sha2'],
                    'blacklist_file_path': '/tmp/hashes_blacklist.txt',
                    'blacklist_is_regex': False
                }
            ]
        }
        self._hash_file_contents = [
            'ffff5f60462c38b1d235cb3509876543',
            'ffff234d2a50a42a87389f1234561a21',
            'ffff51e77b442ee23188d87e4abcdef0'
        ]

        self._domain_config = {
            'blacklists': [
                {
                    'blacklist_name': 'domains',
                    'blacklist_keys': ['osxcollector_domains'],
                    'blacklist_file_path': '/var/domain_blacklist.txt',
                    'blacklist_is_domains': True,
                    'blacklist_is_regex': True
                }
            ]
        }
        self._domain_file_contents = [
            'yelp.com',
            'github.com',
            'example.com'
        ]

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
        self._run_test(input_blobs, expected_blacklists, self._hash_config, self._hash_file_contents)

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
        self._run_test(input_blobs, expected_blacklists, self._hash_config, self._hash_file_contents)

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
        self._run_test(input_blobs, expected_blacklists, self._domain_config, self._domain_file_contents)

    def _run_test(self, input_blobs, expected_blacklists, blacklist_config, blacklist_file_contents):

        output_blobs = run_filter_test(lambda: FindBlacklistedFilter(), input_blobs, config_initial_contents=blacklist_config,
                                       blacklist_file_contents=blacklist_file_contents)

        # added_key, expected_values, input_blobs, output_blobs
        assert_key_added_to_blob('osxcollector_blacklist', expected_blacklists, input_blobs, output_blobs)
