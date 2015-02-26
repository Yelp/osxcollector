# -*- coding: utf-8 -*-
from osxcollector.output_filters.virustotal.lookup_domains import LookupDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class LookupDomainsFilterTest(RunFilterTest):

    def test_no_domains(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]

        self.run_test(LookupDomainsFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)

    def test_benign_domains(self):
        input_blobs = [
            {'osxcollector_domains': ['good.example.com'], 'dingo': 'bingo', 'apple': [3, 14]},
            {'osxcollector_domains': ['good.example.co.uk'], 'bingo': 'bongo', 'orange': 'banana'}
        ]

        self.run_test(LookupDomainsFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)

    def test_suspicious_domains(self):
        input_blobs = [
            {'osxcollector_domains': ['evil.example.com'], 'dingo': 'bingo', 'apple': [3, 14]},
            {'osxcollector_domains': ['evil.example.co.uk'], 'bingo': 'bongo', 'orange': 'banana'}
        ]
        expected_vtdomains = [
            [
                {
                    'domain': 'evil.example.com',
                    'response_code': 1,
                    'detections': {
                        'undetected_referrer_samples': 0,
                        'undetected_communicating_samples': 0,
                        'detected_downloaded_samples': 5,
                        'detected_referrer_samples': 5,
                        'detected_communicating_samples': 5,
                        'detected_urls': 5
                    },
                    'categorization': {}
                }
            ],
            [
                {
                    'domain': 'evil.example.co.uk',
                    'response_code': 1,
                    'detections': {
                        'undetected_referrer_samples': 0,
                        'undetected_communicating_samples': 0,
                        'detected_downloaded_samples': 4,
                        'detected_referrer_samples': 5,
                        'detected_communicating_samples': 5,
                        'detected_urls': 6
                    },
                    'categorization': {}
                }
            ]
        ]
        output_blobs = self.run_test(LookupDomainsFilter, input_blobs=input_blobs)
        self.assert_key_added_to_blob('osxcollector_vtdomain', expected_vtdomains, input_blobs, output_blobs)
