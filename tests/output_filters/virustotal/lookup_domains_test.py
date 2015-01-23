# -*- coding: utf-8 -*-
import mock

from osxcollector.output_filters.virustotal.api import VirusTotalApi
from osxcollector.output_filters.virustotal. \
    lookup_domains import LookupDomainsFilter
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
            {'osxcollector_domains': ['www.example.com'], 'dingo': 'bingo', 'apple': [3, 14]},
            {'osxcollector_domains': ['www.example.co.uk'], 'bingo': 'bongo', 'orange': 'banana'}
        ]

        reports = self.load_reports('./tests/output_filters/virustotal/data/benign_domain_reports.json')
        with mock.patch.object(VirusTotalApi, 'get_domain_reports', autospec=True, return_value=reports) \
                as mock_get_domain_reports:
            self.run_test(LookupDomainsFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)
            mock_get_domain_reports.assert_called_with(mock.ANY, ['www.example.co.uk', 'www.example.com'])

    def test_suspicious_domains(self):
        input_blobs = [
            {'osxcollector_domains': ['www.example.com'], 'dingo': 'bingo', 'apple': [3, 14]},
            {'osxcollector_domains': ['www.example.co.uk'], 'bingo': 'bongo', 'orange': 'banana'}
        ]
        output_blobs = [
            {
                'osxcollector_domains': ['www.example.com'],
                'osxcollector_vtdomain': [
                    {
                        'domain': 'www.example.com',
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
                'dingo': 'bingo',
                'apple': [3, 14]},
            {
                'osxcollector_domains': ['www.example.co.uk'],
                'osxcollector_vtdomain': [
                    {
                        'domain': 'www.example.co.uk',
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
                    }],
                'bingo': 'bongo',
                'orange': 'banana'}
        ]
        reports = self.load_reports('./tests/output_filters/virustotal/data/suspicious_domain_reports.json')

        with mock.patch.object(VirusTotalApi, 'get_domain_reports', autospec=True, return_value=reports) \
                as mock_get_domain_reports:
            self.run_test(LookupDomainsFilter, input_blobs=input_blobs, expected_output_blobs=output_blobs)
            mock_get_domain_reports.assert_called_with(mock.ANY, ['www.example.co.uk', 'www.example.com'])
