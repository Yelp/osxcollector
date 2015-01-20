# -*- coding: utf-8 -*-
from copy import deepcopy

import testify as T
from mock import patch

from osxcollector.output_filters.exceptions import MissingConfigError
from osxcollector.output_filters.util.blacklist import Blacklist
from osxcollector.output_filters.util.blacklist import create_blacklist
from osxcollector.output_filters.util.domains import BadDomainError


class CreateBlacklistTest(T.TestCase):

    @T.setup_teardown
    def setup_file_contents(self):
        file_contents = [
            # Fruits
            'apple', 'banana',

            # Cars
            'corolla', 'datsun'
        ]

        with patch.object(Blacklist, '_read_blacklist_file_contents', return_value=file_contents) as self._file_contents:
            yield

    @T.setup
    def setup_blacklist_date(self):
        self._blacklist_data = {
            'blacklist_name': 'only_required',
            'blacklist_keys': ['fruit_name'],
            'blacklist_file_path': '/who/cares/I/mock/this.txt'
        }

    def test_only_required_keys(self):
        blacklist = create_blacklist(self._blacklist_data)
        T.assert_equal(blacklist.name, self._blacklist_data['blacklist_name'])
        T.assert_equal(blacklist._blacklisted_keys, self._blacklist_data['blacklist_keys'])
        T.assert_equal(blacklist._is_regex, False)
        T.assert_equal(blacklist._is_domains, False)

    def test_missing_required_keys(self):
        for key in self._blacklist_data.keys():
            blacklist_data = deepcopy(self._blacklist_data)
            del blacklist_data[key]
            with T.assert_raises(MissingConfigError):
                create_blacklist(blacklist_data)

    def test_required_with_two_keys(self):
        self._blacklist_data['blacklist_keys'] = ['fruit_name', 'car_name']
        blacklist = create_blacklist(self._blacklist_data)
        T.assert_equal(blacklist._blacklisted_keys, self._blacklist_data['blacklist_keys'])

    def test_keys_not_list(self):
        self._blacklist_data['blacklist_keys'] = 'fruit_name'
        with T.assert_raises(MissingConfigError):
            create_blacklist(self._blacklist_data)

    def test_is_regex(self):
        self._blacklist_data['blacklist_is_regex'] = True
        blacklist = create_blacklist(self._blacklist_data)
        T.assert_equal(blacklist._is_regex, True)

    def test_is_domains(self):
        self._file_contents.return_value = ['apple.com', 'banana.org']

        # Setting 'blacklist_is_domains' overrides 'blacklist_is_regex'
        self._blacklist_data['blacklist_is_domains'] = True
        self._blacklist_data['blacklist_is_regex'] = False
        blacklist = create_blacklist(self._blacklist_data)
        T.assert_equal(blacklist._is_regex, True)
        T.assert_equal(blacklist._is_domains, True)

    def test_bad_domains(self):
        self._blacklist_data['blacklist_is_domains'] = True
        with T.assert_raises(BadDomainError):
            create_blacklist(self._blacklist_data)

    def test_match_fruit(self):
        good_blobs = [
            {'fruit_name': 'apple'},
            {'fruit_name': 'banana'},
        ]

        bad_blobs = [
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        blacklist = create_blacklist(self._blacklist_data)
        for blob in good_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), True)
        for blob in bad_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), False)

    def test_match_fruit_and_cars(self):
        good_blobs = [
            {'fruit_name': 'apple'},
            {'fruit_name': 'banana'},
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        self._blacklist_data['blacklist_keys'] = ['fruit_name', 'car_name']
        blacklist = create_blacklist(self._blacklist_data)
        for blob in good_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), True)

    def test_match_fruit_regex(self):
        good_blobs = [
            {'fruit_name': 'apple'},
        ]

        bad_blobs = [
            {'fruit_name': 'banana'},
            {'car_name': 'corolla'},
            {'car_name': 'datsun'},
        ]

        self._blacklist_data['blacklist_is_regex'] = True
        self._file_contents.return_value = ['app.*', 'ban.+org']
        blacklist = create_blacklist(self._blacklist_data)
        for blob in good_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), True)
        for blob in bad_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), False)

    def test_match_domains(self):
        good_blobs = [
            {'fruit_name': 'apple.com'},
            {'fruit_name': 'www.apple.com'},
            {'fruit_name': 'www.another-thing.apple.com'},
        ]

        bad_blobs = [
            {'fruit_name': 'cran-apple.com'},
            {'fruit_name': 'apple.org'},
            {'fruit_name': 'apple.com.jp'},
            {'car_name': 'apple.com'},
        ]
        self._blacklist_data['blacklist_is_domains'] = True
        self._file_contents.return_value = ['apple.com']
        blacklist = create_blacklist(self._blacklist_data)
        for blob in good_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), True)
        for blob in bad_blobs:
            T.assert_equal(bool(blacklist.match_line(blob)), False)
