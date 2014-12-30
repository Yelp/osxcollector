# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.related_files import RelatedFilesFilter
from tests.output_filters.base_filters.output_filter_test import RunFilterTest


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

    def _test_create_terms(self, initial_terms, expected_terms, blob=None):
        output_filter = RelatedFilesFilter(when=when_anytime, initial_terms=initial_terms)
        if blob:
            output_filter.filter_line(blob)
        output_filter.end_of_lines()
        T.assert_equal(sorted(expected_terms), sorted(output_filter.terms))


class FindUserNamesTest(T.TestCase):

    def test_find_username(self):
        blob = {'osxcollector_username': 'bob'}
        expected = ['bob']

        output_filter = RelatedFilesFilter(when=when_anytime)
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

        output_filter = RelatedFilesFilter(when=when_anytime)
        for blob in blobs:
            output_filter.filter_line(blob)
        T.assert_equal(sorted(expected), sorted(output_filter.usernames))


class RelatedFilesFilterTest(RunFilterTest):

    def test_single_term(self):
        input_blobs = [
            {'banana': '/var/bin/magic_value'}
        ]
        expected_is_related = [
            ['magic_value']
        ]
        initial_terms = ['magic_value']
        self._test_related_files(input_blobs, expected_is_related, initial_terms=initial_terms)

    def test_multi_term(self):
        input_blobs = [
            {'avocado': '/var/bin/magic/hat'},
            {'mango': '/var/bin/value/hat'},
            {'shandy': '/var/bin/magic/value/hat'}
        ]
        expected_is_related = [
            ['magic'],
            ['value'],
            ['magic', 'value']
        ]
        initial_terms = ['magic', 'value']
        self._test_related_files(input_blobs, expected_is_related, initial_terms=initial_terms)

    def test_split_term(self):
        input_blobs = [
            {'avocado': '/var/bin/magic/hat'},
            {'mango': '/var/bin/value/hat'},
            {'shandy': '/var/bin/magic/value/hat'}
        ]
        expected_is_related = [
            ['magic'],
            ['value'],
            ['magic', 'value']
        ]
        initial_terms = ['magic/value']
        self._test_related_files(input_blobs, expected_is_related, initial_terms=initial_terms)

    def test_discover_term(self):
        input_blobs = [
            {'file_path': '/var/bin/magic/value'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            ['magic', 'value'],
            ['magic'],
            ['value'],
            None
        ]
        self._test_related_files(input_blobs, expected_is_related)

    def test_skip_username(self):
        input_blobs = [
            {'file_path': '/var/bin/magic/value', 'osxcollector_username': 'magic'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            ['value'],
            None,
            ['value'],
            None
        ]
        self._test_related_files(input_blobs, expected_is_related)

    def test_when(self):
        def when(blob):
            return 'bingbing' in blob

        input_blobs = [
            {'file_path': '/var/bin/magic', 'bingbing': True, 'osxcollector_username': 'hat'},
            {'file_path': '/var/bin/value'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            ['magic'],
            None,
            ['magic'],
            None,
            None
        ]
        self._test_related_files(input_blobs, expected_is_related, when=when)

    def _test_related_files(self, input_blobs, expected_is_related, when=when_anytime, initial_terms=None):
        output_filter = RelatedFilesFilter(when=when, initial_terms=initial_terms)
        output_blobs = self._run_filter(output_filter, input_blobs)

        actual_is_related = list(blob.get('osxcollector_related', {}).get('files', None) for blob in output_blobs)
        for actual, expected in zip(actual_is_related, expected_is_related):
            actual = sorted(actual) if actual else actual
            expected = sorted(expected) if expected else expected
            T.assert_equal(actual, expected)

        # Minus 'osxcollector_related' key, the input should be unchanged
        for input_blob, output_blob in zip(input_blobs, output_blobs):
            if 'osxcollector_related' in output_blob:
                del output_blob['osxcollector_related']
            T.assert_equal(input_blob, output_blob)
