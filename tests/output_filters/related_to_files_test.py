# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.related_to_files import RelatedToFilesFilter


def when_anytime(blob):
    return True


class CreateTermsTest(T.TestCase):

    def test_single_term(self):
        initial_terms = ['one_word']
        expected = ['one_word']
        self._test_create_terms(initial_terms, expected)

    def test_multi_terms(self):
        initial_terms = ['one_word', 'pants', 'face']
        expected = ['one_word', 'pants', 'face']
        self._test_create_terms(initial_terms, expected)

    def test_split_terms(self):
        initial_terms = ['/ivanlei/source/osxcollector']
        expected = ['ivanlei', 'source', 'osxcollector']
        self._test_create_terms(initial_terms, expected)

    def test_whitelist_terms(self):
        initial_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['ivanlei', 'source', 'osxcollector', 'virtual_envs']
        self._test_create_terms(initial_terms, expected)

    def test_whitelist_username_terms(self):
        initial_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['source', 'osxcollector', 'virtual_envs']
        blob = {'osxcollector_username': 'ivanlei'}

        self._test_create_terms(initial_terms, expected, blob)

    def _test_create_terms(self, initial_terms, expected, blob=None):
        output_filter = RelatedToFilesFilter(when=when_anytime, initial_terms=initial_terms)
        if blob:
            output_filter.filter_line(blob)
        output_filter.end_of_lines()
        T.assert_equal(sorted(expected), sorted(output_filter._terms))


class FindUserNamesTest(T.TestCase):

    def test_find_username(self):
        blob = {'osxcollector_username': 'bob'}
        expected = ['bob']

        output_filter = RelatedToFilesFilter(when=when_anytime)
        output_filter.filter_line(blob)
        T.assert_equal(sorted(expected), sorted(output_filter._usernames))

    def test_find_multiple_username(self):
        blobs = [
            {'osxcollector_username': 'bob'},
            {'osxcollector_username': 'jim'},
            {'osxcollector_username': 'bob'},
            {'banana': 'pants'}
        ]
        expected = ['bob', 'jim']

        output_filter = RelatedToFilesFilter(when=when_anytime)
        for blob in blobs:
            output_filter.filter_line(blob)
        T.assert_equal(sorted(expected), sorted(output_filter._usernames))
