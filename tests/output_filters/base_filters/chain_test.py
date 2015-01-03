# -*- coding: utf-8 -*-
import testify as T
from osxcollector.output_filters.base_filters.chain import ChainFilter
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from tests.output_filters.run_filter_test import run_filter_test


def make_chain_filter():
    chain = [
        OutputFilter(),
        OutputFilter()
    ]
    return ChainFilter(chain)


class ChainFilterTest(T.TestCase):

    def test_run_output_filter(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]
        run_filter_test(make_chain_filter, input_blobs, expected_output_blobs=input_blobs)
