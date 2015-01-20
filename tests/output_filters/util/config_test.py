# -*- coding: utf-8 -*-
import testify as T
from mock import patch

from osxcollector.output_filters.util.config import config_get_deep


class CreateBlacklistTest(T.TestCase):

    @T.setup_teardown
    def patch_config(self):
        config_initial_contents = {
            'a': 'b',
            'c': {'d': 'e'},
            'f': 1,
            'g': ['apple', 'banana']
        }

        with patch('osxcollector.output_filters.util.config._read_config', return_value=config_initial_contents):
            yield

    def test_read_top_level_key(self):
        T.assert_equal('b', config_get_deep('a'))

    def test_read_multi_level_key(self):
        T.assert_equal('e', config_get_deep('c.d'))

    def test_numeric_val(self):
        T.assert_equal(1, config_get_deep('f'))

    def test_list_val(self):
        T.assert_equal(['apple', 'banana'], config_get_deep('g'))
