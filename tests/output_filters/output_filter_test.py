# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.output_filter import OutputFilter


class OutputFilterTest(T.TestCase):

    @T.setup
    def setup_inputs(self):
        self._output_filter = OutputFilter()
        self._inputs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]

    def test_filter_line(self):
        for blob in self._inputs:
            output = self._output_filter.filter_line(blob)
            T.assert_equal(output, blob)
