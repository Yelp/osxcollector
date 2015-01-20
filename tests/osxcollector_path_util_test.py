# -*- coding: utf-8 -*-
import testify as T

from osxcollector import osxcollector


class PathUtilsTestCase(T.TestCase):

    def _test_pathjoin(self, expected, path, *args):
        T.assert_equal(expected, osxcollector.pathjoin(path, *args))

    def test_all_relative(self):
        self._test_pathjoin('foo/bar/whiz', 'foo', 'bar', 'whiz')

    def test_rooted_and_relative(self):
        self._test_pathjoin('/foo/bar/whiz', '/foo', 'bar', 'whiz')

    def test_rooted_and_rooted(self):
        self._test_pathjoin('/foo/bar/whiz/bang/boom/wow', '/foo', '/bar', '/whiz', 'bang', '/boom/wow')

    def test_single_arg(self):
        self._test_pathjoin('/foo/bar', '/foo/bar')
