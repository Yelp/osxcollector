# -*- coding: utf-8 -*-
from __future__ import absolute_import

from osxcollector import osxcollector


class TestPathUtils:

    def _test_pathjoin(self, expected, path, *args):
        assert expected == osxcollector.pathjoin(path, *args)

    def test_all_relative(self):
        self._test_pathjoin('foo/bar/whiz', 'foo', 'bar', 'whiz')

    def test_rooted_and_relative(self):
        self._test_pathjoin('/foo/bar/whiz', '/foo', 'bar', 'whiz')

    def test_rooted_and_rooted(self):
        self._test_pathjoin('/foo/bar/whiz/bang/boom/wow', '/foo', '/bar', '/whiz', 'bang', '/boom/wow')

    def test_single_arg(self):
        self._test_pathjoin('/foo/bar', '/foo/bar')
