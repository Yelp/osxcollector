# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.domains import BadDomainError
from osxcollector.output_filters.domains import clean_domain
from osxcollector.output_filters.domains import DomainsFilter


class DomainsFilterTest(T.TestCase):

    @T.setup
    def setup_inputs(self):
        self._output_filter = DomainsFilter()

    def test_tld(self):
        blob = {'fungo': 'http://www.example.com'}
        expected = [u'www.example.com']
        self._test_look_for_domains(blob, expected)

    def test_bare_domain(self):
        blob = {'fungo': 'http://example.com'}
        expected = [u'example.com']
        self._test_look_for_domains(blob, expected)

    def test_uk_domain(self):
        blob = {'fungo': 'http://www.example.co.uk'}
        expected = [u'www.example.co.uk']
        self._test_look_for_domains(blob, expected)

    def test_info_domain(self):
        blob = {'fungo': 'http://www.example.info'}
        expected = [u'www.example.info']
        self._test_look_for_domains(blob, expected)

    def test_ftp_scheme(self):
        blob = {'fungo': 'ftp://www.example.com'}
        expected = [u'www.example.com']
        self._test_look_for_domains(blob, expected)

    def test_domain_in_path(self):
        blob = {'fungo': 'http://www.example.com/bango?p=http://www.dingo.com'}
        expected = [u'www.example.com', u'www.dingo.com']
        self._test_look_for_domains(blob, expected)

    def test_quoted_domain(self):
        blob = {'fungo': 'http%3A//www.example.com'}
        expected = [u'www.example.com']
        self._test_look_for_domains(blob, expected)

    def test_quoted_in_path(self):
        blob = {'fungo': 'http://www.example.com/bango?p=http%3A//www.dingo.co.uk'}
        expected = [u'www.example.com', u'www.dingo.co.uk']
        self._test_look_for_domains(blob, expected)

    def test_domain_in_key(self):
        blob = {'http://www.example.com': 'zungo'}
        expected = [u'www.example.com']
        self._test_look_for_domains(blob, expected)

    def test_list(self):
        blob = {'fungo': ['http://www.example.com', 'https://www.zzz.sample.org']}
        expected = [u'www.example.com', u'www.zzz.sample.org']
        self._test_look_for_domains(blob, expected)

    def test_dict(self):
        blob = {'fungo': {'http://www.example.com': 'https://www.zzz.sample.org'}}
        expected = [u'www.example.com', u'www.zzz.sample.org']
        self._test_look_for_domains(blob, expected)

    def test_list_of_dict(self):
        blob = {'fungo': [{'http://www.example.com': 'https://www.zzz.sample.org'}, {'a': 'https://www.dingo.co.uk'}]}
        expected = [u'www.example.com', u'www.zzz.sample.org', u'www.dingo.co.uk']
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
            u'www.example.com',
            u'www.example2.com',
            u'www.example3.com',
            u'example4.com',
            u'www.xxx.yyy.zzz.example.com'
        ]
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
