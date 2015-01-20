# -*- coding: utf-8 -*-
import testify as T

from osxcollector.output_filters.opendns. \
    related_domains import RelatedDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class RelatedDomainsFilterTest(RunFilterTest):

    def test_no_domains(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
        ]
        output_blobs = self.run_test(RelatedDomainsFilter, input_blobs=input_blobs)
        T.assert_equal(1, len(output_blobs))

        T.assert_not_in('osxcollector_related', output_blobs[0])
