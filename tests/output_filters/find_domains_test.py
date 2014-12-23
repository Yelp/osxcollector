# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.find_domains import BadDomainError
from osxcollector.output_filters.find_domains import FindDomainsFilter
from osxcollector.output_filters.find_domains import clean_domain


class FindDomainsFilterTest(T.TestCase):

    @T.setup
    def setup_inputs(self):
        self._output_filter = FindDomainsFilter()

    def test_tld(self):
        blob = {'fungo': 'http://www.example.com'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def test_bare_domain(self):
        blob = {'fungo': 'http://example.com'}
        expected = ['example.com']
        self._test_look_for_domains(blob, expected)

    def test_uk_domain(self):
        blob = {'fungo': 'http://www.example.co.uk'}
        expected = ['www.example.co.uk', 'example.co.uk']
        self._test_look_for_domains(blob, expected)

    def test_info_domain(self):
        blob = {'fungo': 'http://www.example.info'}
        expected = ['www.example.info', 'example.info']
        self._test_look_for_domains(blob, expected)

    def test_ftp_scheme(self):
        blob = {'fungo': 'ftp://www.example.com'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def test_domain_in_path(self):
        blob = {'fungo': 'http://www.example.com/bango?p=http://www.dingo.com'}
        expected = ['www.example.com', 'www.dingo.com', 'example.com', 'dingo.com']
        self._test_look_for_domains(blob, expected)

    def test_quoted_domain(self):
        blob = {'fungo': 'http%3A//www.example.com'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def test_quoted_in_path(self):
        blob = {'fungo': 'http://www.example.com/bango?p=http%3A//www.dingo.co.uk'}
        expected = ['www.example.com', 'www.dingo.co.uk', 'example.com', 'dingo.co.uk']
        self._test_look_for_domains(blob, expected)

    def test_domain_in_key(self):
        blob = {'http://www.example.com': 'zungo'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def test_list(self):
        blob = {'fungo': ['http://www.example.com', 'https://www.zzz.sample.org']}
        expected = ['www.example.com', 'www.zzz.sample.org', 'example.com', 'sample.org']
        self._test_look_for_domains(blob, expected)

    def test_dict(self):
        blob = {'fungo': {'http://www.example.com': 'https://www.zzz.sample.org'}}
        expected = ['www.example.com', 'www.zzz.sample.org', 'example.com', 'sample.org']
        self._test_look_for_domains(blob, expected)

    def test_list_of_dict(self):
        blob = {'fungo': [{'http://www.example.com': 'https://www.zzz.sample.org'}, {'a': 'https://www.dingo.co.uk'}]}
        expected = ['www.example.com', 'www.zzz.sample.org', 'www.dingo.co.uk', 'example.com', 'sample.org', 'dingo.co.uk']
        self._test_look_for_domains(blob, expected)

    def test_tokenizing(self):
        blob = {'fungo': [
            '{"bar":\'http://www.example.com\'}',
            '(http://www.example2.com)',
            ';http://www.example3.com\n',
            'http://example4.com.',
            '#@^%$*http://www.xxx.yyy.zzz.example.com/fungo/digno'
        ]}
        expected = [
            'www.example.com', 'example.com',
            'www.example2.com', 'example2.com',
            'www.example3.com', 'example3.com',
            'example4.com',
            'www.xxx.yyy.zzz.example.com'
        ]
        self._test_look_for_domains(blob, expected)

    def test_special_keys_domain(self):
        blob = {'host': 'www.example.com'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def test_special_keys_url(self):
        blob = {'host': 'https://www.example.com'}
        expected = ['www.example.com', 'example.com']
        self._test_look_for_domains(blob, expected)

    def _test_look_for_domains(self, blob, domains):
        output = self._output_filter.filter_line(blob)
        T.assert_equal(sorted(output.get('osxcollector_domains', None)), sorted(domains))


class clean_domain_Test(T.TestCase):

    def _test_clean_domain(self, dirty_domain, expected):
        domain = clean_domain(dirty_domain)
        T.assert_equal(domain, expected)

    def test_trailing_and_leading_dots(self):
        self._test_clean_domain('.www.example.com.', 'www.example.com')

    def test_trailing_and_leading_slashes(self):
        self._test_clean_domain('//www.example.com//', 'www.example.com')

    def test_single_word(self):
        with T.assert_raises(BadDomainError):
            clean_domain('oneword')
