# -*- coding: utf-8 -*-
from contextlib import nested
from StringIO import StringIO

import simplejson
import testify as T
from mock import patch
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter


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

    def test_end_of_lines(self):
        output = self._output_filter.end_of_lines()
        T.assert_equal(output, [])


class RunFilterTest(T.TestCase):

    def _run_filter(self, output_filter, input_blobs, expected_output_blobs=None):
        input_lines = '\n'.join([simplejson.dumps(blob) for blob in input_blobs])

        with nested(
                patch('sys.stdin', StringIO(input_lines)),
                patch('sys.stdout', new_callable=StringIO)
        ) as (
            mock_stdin,
            mock_stdout
        ):

            run_filter(output_filter)
            output_lines = [line for line in mock_stdout.getvalue().split('\n') if len(line)]
            output_blobs = [simplejson.loads(line) for line in output_lines]

            if expected_output_blobs:
                T.assert_equal(len(output_blobs), len(expected_output_blobs))

                for expected_blob, actual_blob in zip(expected_output_blobs, output_blobs):
                    T.assert_equal(expected_blob, actual_blob)

            return output_blobs

    def test_output_filter(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]
        output_filter = OutputFilter()
        self._run_filter(output_filter, input_blobs, input_blobs)
