# -*- coding: utf-8 -*-
from __future__ import absolute_import

from osxcollector import osxcollector


class TestDateUtils:

    def test_link_path_to_chain(self):
        # test an empty path
        empty_path = ''
        empty_chain = osxcollector.DictUtils._link_path_to_chain(empty_path)
        assert empty_chain == []

        # test path given as list
        path_as_list = ['Session', 'Items']
        chain_as_list = osxcollector.DictUtils._link_path_to_chain(path_as_list)
        assert path_as_list == chain_as_list

        # test path given as tuple
        path_as_tuple = ('Session', 'Items')
        chain_as_tuple = osxcollector.DictUtils._link_path_to_chain(path_as_tuple)
        assert path_as_tuple == chain_as_tuple

        # test path given as set
        path_as_set = {'Session', 'Items'}
        chain_as_set = osxcollector.DictUtils._link_path_to_chain(path_as_set)
        assert path_as_set == chain_as_set

        # test path given as string delimited with .
        path_as_string = 'Session.Items'
        chain = osxcollector.DictUtils._link_path_to_chain(path_as_string)
        assert path_as_list == chain

    def test_get_deep_by_chain(self):
        d = {
            'Session': {
                'Items': 'test-items',
                'Account': ['account1', 'account2'],
            },
            23: 'twenty-three',
        }

        # test two-element path
        val1 = osxcollector.DictUtils._get_deep_by_chain(d, ['Session', 'Items'])
        assert 'test-items' == val1

        # test simple path with numerical key
        val2 = osxcollector.DictUtils._get_deep_by_chain(d, ['23'])
        assert 'twenty-three' == val2

        # test default value parameter
        val_default = osxcollector.DictUtils._get_deep_by_chain(d, ['User', 'Name'], 'John Doe')
        assert 'John Doe' == val_default

    def test_get_deep(self):
        d = {
            'SessionItems': {
                'CustomListItems': 'list items',
                'Default': 'default list item',
            },
            'SessionId': 140,
        }

        # test no default value on en mpty path
        no_path_no_default = osxcollector.DictUtils.get_deep(d)
        assert no_path_no_default is None

        # test default value on en mpty path
        no_path_default_value = osxcollector.DictUtils.get_deep(d, default=43)
        assert 43 == no_path_default_value

        # test default value on wrong path
        wrong_path_default_value = osxcollector.DictUtils.get_deep(d, 'SessionItems.ListItems', 'no items')
        assert 'no items' == wrong_path_default_value

        # test no default value on wring path
        wrong_path_default_value = osxcollector.DictUtils.get_deep(d, 'SessionItems.ListItems')
        assert wrong_path_default_value is None

        # test correct path
        value = osxcollector.DictUtils.get_deep(d, 'SessionItems.CustomListItems', 'no items')
        assert 'list items' == value
