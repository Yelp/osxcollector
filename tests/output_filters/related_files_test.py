# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.related_files import RelatedFilesFilter
from tests.output_filters.run_filter_test import assert_key_added_to_blob
from tests.output_filters.run_filter_test import run_filter_test


def when_anytime(blob):
    return True


class RelatedFilesFilterTest(T.TestCase):

    @T.teardown
    def teardown_outputfilter(self):
        self._output_filter = None

    def _run_filter_test(self, input_blobs=None, initial_terms=None, expected_terms=None,
                         expected_usernames=None, when=when_anytime, expected_is_related=None):

        def create_related_files_filter():
            self._output_filter = RelatedFilesFilter(when=when, initial_terms=initial_terms)
            return self._output_filter

        output_blobs = run_filter_test(create_related_files_filter, input_blobs=input_blobs)
        if expected_terms:
            T.assert_equal(sorted(expected_terms), sorted(self._output_filter.terms))
        if expected_usernames:
            T.assert_equal(sorted(expected_usernames), sorted(self._output_filter.usernames))
        if expected_is_related:
            assert_key_added_to_blob('osxcollector_related', expected_is_related, input_blobs, output_blobs)
        return output_blobs


class CreateTermsTest(RelatedFilesFilterTest):

    def test_single_term(self):
        initial_terms = ['one_word']
        expected = ['one_word']
        self._run_filter_test(initial_terms=initial_terms, expected_terms=expected)

    def test_multi_terms(self):
        initial_terms = ['one_word', 'pants', 'face']
        expected = ['one_word', 'pants', 'face']
        self._run_filter_test(initial_terms=initial_terms, expected_terms=expected)

    def test_split_terms(self):
        initial_terms = ['/ivanlei/source/osxcollector']
        expected = ['ivanlei', 'source', 'osxcollector']
        self._run_filter_test(initial_terms=initial_terms, expected_terms=expected)

    def test_whitelist_terms(self):
        initial_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['ivanlei', 'source', 'osxcollector', 'virtual_envs']
        self._run_filter_test(initial_terms=initial_terms, expected_terms=expected)

    def test_whitelist_username_terms(self):
        initial_terms = ['/Users/ivanlei/source/osxcollector', '/Users/ivanlei/virtual_envs/osxcollector/bin/python']
        expected = ['source', 'osxcollector', 'virtual_envs']
        blob = {'osxcollector_username': 'ivanlei'}

        self._run_filter_test(input_blobs=[blob], initial_terms=initial_terms, expected_terms=expected, expected_usernames=['ivanlei'])


class FindUserNamesTest(RelatedFilesFilterTest):

    def test_find_username(self):
        blob = {'osxcollector_username': 'bob'}
        self._run_filter_test(input_blobs=[blob], expected_usernames=['bob'])

    def test_find_multiple_username(self):
        blobs = [
            {'osxcollector_username': 'bob'},
            {'osxcollector_username': 'jim'},
            {'osxcollector_username': 'bob'},
            {'banana': 'pants'}
        ]
        expected = ['bob', 'jim']
        self._run_filter_test(input_blobs=blobs, expected_usernames=expected)


class RelatedFilesFilterTest(RelatedFilesFilterTest):

    def test_single_term(self):
        input_blobs = [
            {'banana': '/var/bin/magic_value'}
        ]
        expected_is_related = [
            {'files': ['magic_value']}
        ]
        initial_terms = ['magic_value']
        self._run_filter_test(input_blobs=input_blobs, initial_terms=initial_terms, expected_is_related=expected_is_related)

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
        initial_terms = ['magic', 'value']
        self._run_filter_test(input_blobs=input_blobs, initial_terms=initial_terms, expected_is_related=expected_is_related)

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
        initial_terms = ['magic/value']
        self._run_filter_test(input_blobs=input_blobs, initial_terms=initial_terms, expected_is_related=expected_is_related)

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
        self._run_filter_test(input_blobs=input_blobs, expected_is_related=expected_is_related)

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
        self._run_filter_test(input_blobs=input_blobs, expected_is_related=expected_is_related)

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
        self._run_filter_test(input_blobs=input_blobs, when=when_binbing, expected_is_related=expected_is_related)
