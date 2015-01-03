# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.find_domains import FindDomainsFilter
from tests.output_filters.run_filter_test import assert_key_added_to_blob
from tests.output_filters.run_filter_test import run_filter_test


class FindDomainsFilterTest(T.TestCase):

    @T.setup
    def setup_inputs(self):
        self._output_filter = FindDomainsFilter()

    def _run_test(self, input_blob, expected_domains):
        output_blobs = run_filter_test(lambda: FindDomainsFilter(), [input_blob])
        assert_key_added_to_blob('osxcollector_domains', [expected_domains], [input_blob], output_blobs)

    def test_no_domain(self):
        input_blob = {'fungo': 'kidney'}
        self._run_test(input_blob, None)

    def test_tld(self):
        input_blob = {'fungo': 'http://www.example.com'}
        expected_domains = ['example.com', 'www.example.com']
        self._run_test(input_blob, expected_domains)

    def test_bare_domain(self):
        input_blob = {'fungo': 'http://example.com'}
        expected_domains = ['example.com']
        self._run_test(input_blob, expected_domains)

    def test_uk_domain(self):
        input_blob = {'fungo': 'http://www.example.co.uk'}
        expected_domains = ['example.co.uk', 'www.example.co.uk']
        self._run_test(input_blob, expected_domains)

    def test_info_domain(self):
        input_blob = {'fungo': 'http://www.example.info'}
        expected_domains = ['example.info', 'www.example.info']
        self._run_test(input_blob, expected_domains)

    def test_ftp_scheme(self):
        input_blob = {'fungo': 'ftp://example.com'}
        expected_domains = ['example.com']
        self._run_test(input_blob, expected_domains)

    def test_domain_in_path(self):
        input_blob = {'fungo': 'http://www.example.com/bango?p=http://www.dingo.com'}
        expected_domains = [
            'dingo.com',
            'example.com',
            'www.dingo.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_quoted_domain(self):
        input_blob = {'fungo': 'http%3A//www.example.com'}
        expected_domains = [
            'example.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_quoted_in_path(self):
        input_blob = {'fungo': 'http://www.example.com/bango?p=http%3A//www.dingo.co.uk'}
        expected_domains = [
            'dingo.co.uk',
            'example.com',
            'www.dingo.co.uk',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_domain_in_key(self):
        input_blob = {'http://www.example.com': 'zungo'}
        expected_domains = [
            'example.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_list(self):
        input_blob = {'fungo': ['http://www.example.com', 'https://www.zzz.sample.org']}
        expected_domains = [
            'example.com',
            'sample.org',
            'www.example.com',
            'www.zzz.sample.org'
        ]
        self._run_test(input_blob, expected_domains)

    def test_dict(self):
        input_blob = {'fungo': {'http://www.example.com': 'https://www.zzz.sample.org'}}
        expected_domains = [
            'example.com',
            'sample.org',
            'www.example.com',
            'www.zzz.sample.org'
        ]
        self._run_test(input_blob, expected_domains)

    def test_list_of_dict(self):
        input_blob = {
            'fungo': [
                {'http://www.example.com': 'https://www.zzz.sample.org'},
                {'a': 'https://www.dingo.co.uk'}
            ]
        }
        expected_domains = [
            'dingo.co.uk',
            'example.com',
            'sample.org',
            'www.dingo.co.uk',
            'www.example.com',
            'www.zzz.sample.org'
        ]
        self._run_test(input_blob, expected_domains)

    def test_tokenizing(self):
        input_blob = {
            'fungo': [
                '{"bar":\'http://www.example.com\'}',
                '(http://www.example2.com)',
                ';http://www.example3.com\n',
                'http://example4.com.',
                '#@^%$*http://www.xxx.yyy.zzz.example.com/fungo/digno'
            ]
        }
        expected_domains = [
            'example.com',
            'example2.com',
            'example3.com',
            'example4.com',
            'www.example.com',
            'www.example2.com',
            'www.example3.com',
            'www.xxx.yyy.zzz.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_special_keys_domain(self):
        input_blob = {'host': 'www.example.com'}
        expected_domains = [
            'example.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_no_dupes(self):
        input_blob = {
            'host': 'www.example.com',
            'another_thing': 'http://www.example.com',
            'https://www.example.com': True,
            'dictation': {'threepete': ['ftp://example.com', 'http://example.com', 'https://www.example.com']}
        }
        expected_domains = [
            'example.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)

    def test_special_keys_url(self):
        input_blob = {'host': 'https://www.example.com'}
        expected_domains = [
            'example.com',
            'www.example.com'
        ]
        self._run_test(input_blob, expected_domains)
