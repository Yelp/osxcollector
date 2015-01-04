# -*- coding: utf-8 -*-
from osxcollector.output_filters.opendns. \
    related_domains import RelatedDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class RelatedDomainsFilterTest(RunFilterTest):

    def test_no_domains(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]

        self.run_test(lambda: RelatedDomainsFilter(), input_blobs=input_blobs, expected_output_blobs=input_blobs)
