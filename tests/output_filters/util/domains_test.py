# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.util.domains import clean_domain
from osxcollector.output_filters.util.domains import expand_domain


class CleanDomainTest(T.TestCase):

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


class ExpandDomainTest(T.TestCase):

    def test_simple_subdomain(self):
        self._test_expand_domain('www.example.com', ['example.com', 'www.example.com'])

    def test_no_subdomain(self):
        self._test_expand_domain('example.com', ['example.com'])

    def test_complex_subdomain(self):
        self._test_expand_domain('www.foo.bar.whiz.example.com', ['example.com', 'www.foo.bar.whiz.example.com'])

    def _test_expand_domain(self, initial_domain, expected):
        expanded = list(expand_domain(initial_domain))
        T.assert_equal(sorted(expanded), sorted(expected))
