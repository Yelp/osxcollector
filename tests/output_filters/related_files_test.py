# -*- coding: utf-8 -*-
import testify as T

from osxcollector.output_filters.related_files import RelatedFilesFilter
from tests.output_filters.run_filter_test import assert_equal_sorted
from tests.output_filters.run_filter_test import RunFilterTest


def when_anytime(blob):
    """A simple when that always returns True"""
    return True


class RelatedFilesFilterTest(RunFilterTest):

    """Created a RelateFilesFilter, calls run_test, and performs additional filter specific validation."""

    @T.teardown
    def teardown_outputfilter(self):
        self._output_filter = None

    def _run_test(self, input_blobs=None, when=when_anytime, file_terms=None, expected_terms=None,
                  expected_usernames=None, expected_is_related=None):
        """Created a RelateFilesFilter, calls run_test, and performs additional filter specific validation.

        Args:
            input_blob: An enumerable of dicts
            when: A callable when to init the RelatedFilesFilter with
            file_terms: An enumerable of strings to init the RelatedFilesFilter with
            expected_terms: The expected final value of RelatedFilesFilter.terms
            expected_usernames: The expected final value of RelatedFilesFilter.usernames
            expected_is_related: An enumerable of the expected value of 'osxcollector_related' for each output_blob
        """

        def create_related_files_filter():
            self._output_filter = RelatedFilesFilter(when=when, file_terms=file_terms)
            return self._output_filter

        output_blobs = self.run_test(create_related_files_filter, input_blobs=input_blobs)
        if expected_terms:
            assert_equal_sorted(expected_terms, self._output_filter.terms)
        if expected_usernames:
            assert_equal_sorted(expected_usernames, self._output_filter.usernames)
        if expected_is_related:
            self.assert_key_added_to_blob('osxcollector_related', expected_is_related, input_blobs, output_blobs)
        return output_blobs


class CreateTermsTest(RelatedFilesFilterTest):

    """Focuses on testing that terms are properly created."""

    def test_single_term(self):
        file_terms = ['one_word']
        expected = ['one_word']
        self._run_test(file_terms=file_terms, expected_terms=expected)

    def test_multi_terms(self):
        file_terms = ['one_word', 'pants', 'face']
        expected = ['one_word', 'pants', 'face']
        self._run_test(file_terms=file_terms, expected_terms=expected)

    def test_split_terms(self):
        file_terms = ['/ivanlei/source/osxcollector']
        expected = ['ivanlei', 'source', 'osxcollector']
        self._run_test(file_terms=file_terms, expected_terms=expected)

    def test_whitelist_terms(self):
        file_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['ivanlei', 'source', 'osxcollector', 'virtual_envs']
        self._run_test(file_terms=file_terms, expected_terms=expected)

    def test_whitelist_username_terms(self):
        file_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['source', 'osxcollector', 'virtual_envs']
        blob = {'osxcollector_username': 'ivanlei'}
        expected_usernames = ['ivanlei']

        self._run_test(input_blobs=[blob], file_terms=file_terms, expected_terms=expected, expected_usernames=expected_usernames)


class FindUserNamesTest(RelatedFilesFilterTest):

    """Focuses on ensuring that usernames are found so they can be ignored as terms."""

    def test_find_username(self):
        blob = {'osxcollector_username': 'bob'}
        expected_usernames = ['bob']
        self._run_test(input_blobs=[blob], expected_usernames=expected_usernames)

    def test_find_multiple_username(self):
        blobs = [
            {'osxcollector_username': 'bob'},
            {'osxcollector_username': 'jim'},
            {'osxcollector_username': 'bob'},
            {'banana': 'pants'}
        ]
        expected_usernames = ['bob', 'jim']
        self._run_test(input_blobs=blobs, expected_usernames=expected_usernames)


class RelatedFilesFilterTest(RelatedFilesFilterTest):

    """Tests the overall functionality of the filter."""

    def test_single_term(self):
        input_blobs = [
            {'banana': '/var/bin/magic_value'}
        ]
        expected_is_related = [
            {'files': ['magic_value']}
        ]
        file_terms = ['magic_value']
        self._run_test(input_blobs=input_blobs, file_terms=file_terms, expected_is_related=expected_is_related)

    def test_multi_term(self):
        input_blobs = [
            {'avocado': '/var/bin/magic/hat'},
            {'mango': '/var/bin/value/hat'},
            {'shandy': '/var/bin/magic/value/hat'}
        ]
        expected_is_related = [
            {'files': ['magic']},
            {'files': ['value']},
            {'files': ['magic', 'value']}
        ]
        file_terms = ['magic', 'value']
        self._run_test(input_blobs=input_blobs, file_terms=file_terms, expected_is_related=expected_is_related)

    def test_split_term(self):
        input_blobs = [
            {'avocado': '/var/bin/magic/hat'},
            {'mango': '/var/bin/value/hat'},
            {'shandy': '/var/bin/magic/value/hat'}
        ]
        expected_is_related = [
            {'files': ['magic']},
            {'files': ['value']},
            {'files': ['magic', 'value']}
        ]
        file_terms = ['magic/value']
        self._run_test(input_blobs=input_blobs, file_terms=file_terms, expected_is_related=expected_is_related)

    def test_discover_term(self):
        input_blobs = [
            {'file_path': '/var/bin/magic/value'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            {'files': ['magic', 'value']},
            {'files': ['magic']},
            {'files': ['value']},
            None
        ]
        self._run_test(input_blobs=input_blobs, expected_is_related=expected_is_related)

    def test_skip_username(self):
        input_blobs = [
            {'file_path': '/var/bin/magic/value', 'osxcollector_username': 'magic'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            {'files': ['value']},
            None,
            {'files': ['value']},
            None
        ]
        self._run_test(input_blobs=input_blobs, expected_is_related=expected_is_related)

    def test_when(self):
        def when_binbing(blob):
            return 'bingbing' in blob

        input_blobs = [
            {'file_path': '/var/bin/magic', 'bingbing': True, 'osxcollector_username': 'hat'},
            {'file_path': '/var/bin/value'},
            {'carrot': '/var/bin/magic/hat'},
            {'apple': '/var/bin/value/hat'},
            {'lemmon': '/lime/rickey'}
        ]
        expected_is_related = [
            {'files': ['magic']},
            None,
            {'files': ['magic']},
            None,
            None
        ]
        self._run_test(input_blobs=input_blobs, when=when_binbing, expected_is_related=expected_is_related)
