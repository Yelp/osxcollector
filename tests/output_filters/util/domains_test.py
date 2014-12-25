# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.util.domains import clean_domain


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
