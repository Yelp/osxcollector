# -*- coding: utf-8 -*-
import mock

from osxcollector.output_filters.virustotal.api import VirusTotalApi
from osxcollector.output_filters.virustotal. \
    lookup_hashes import LookupHashesFilter
from tests.output_filters.run_filter_test import RunFilterTest


class LookupHashesFilterTest(RunFilterTest):

    def test_no_hashes(self):
        input_blobs = [
            {'fungo': 'dingo', 'bingo': [11, 37], 'banana': {'a': 11}},
            {'span': 'div', 'head': ['tail', 22], 'orange': {'lemmon': 'zits'}}
        ]
        self.run_test(LookupHashesFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)

    def test_benign_hashes(self):
        input_blobs = [
            {'sha2': 'b8d99a20b148b6906977922ce2f964748c70cc36d5c5806a5c41ac9cb50f16d7', 'dingo': 'bingo', 'apple': [3, 14]},
            {'sha2': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c', 'bingo': 'bongo', 'orange': 'banana'}
        ]

        reports = self.load_reports('./tests/output_filters/virustotal/data/benign_file_reports.json')
        with mock.patch.object(VirusTotalApi, 'get_file_reports', autospec=True, return_value=reports) \
                as mock_get_file_reports:
            self.run_test(LookupHashesFilter, input_blobs=input_blobs, expected_output_blobs=input_blobs)
            mock_get_file_reports.assert_called_with(mock.ANY, [
                '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
                'b8d99a20b148b6906977922ce2f964748c70cc36d5c5806a5c41ac9cb50f16d7'
            ])

    def test_suspicious_hashes(self):
        input_blobs = [
            {'sha2': 'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302', 'dingo': 'bingo', 'apple': [3, 14]},
            {'sha2': '6e87855371171d912dd866e8d7747bf965c80053f83259827a55826ca38a9360', 'bingo': 'bongo', 'orange': 'banana'}
        ]
        output_blobs = [
            {
                'sha2': 'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302',
                'osxcollector_vthash': [{
                    'scan_id': 'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302-1273894724',
                    'sha1': 'da9b79f2fd33d002033b69a9a346af4671a9e16b',
                    'sha256': 'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302',
                    'md5': '0c71d8cedc8bbb2b619a76d1478c4348',
                    'scan_date': '2015-01-15 16:42:01',
                    'permalink': 'https://www.virustotal.com/file/'
                    + 'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302/analysis/1273894724/',
                    'total': 40,
                    'positives': 40,
                    'response_code': 1
                }],
                'dingo': 'bingo',
                'apple': [3, 14]
            },
            {
                'sha2': '6e87855371171d912dd866e8d7747bf965c80053f83259827a55826ca38a9360',
                'osxcollector_vthash': [{
                    'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
                    'sha1': '92e3750a9f0eef6290dd83867eff88064e9c01bb',
                    'sha256': '6e87855371171d912dd866e8d7747bf965c80053f83259827a55826ca38a9360',
                    'md5': '06506cc06cf0167ea583de62c98eae2c',
                    'scan_date': '2010-05-15 03:38:44',
                    'permalink': 'https://www.virustotal.com/file/'
                    + '6e87855371171d912dd866e8d7747bf965c80053f83259827a55826ca38a9360/analysis/1273894724/',
                    'total': 40,
                    'positives': 40,
                    'response_code': 1
                }],
                'bingo': 'bongo',
                'orange': 'banana'}
        ]

        reports = self.load_reports('./tests/output_filters/virustotal/data/suspicious_file_reports.json')
        with mock.patch.object(VirusTotalApi, 'get_file_reports', autospec=True, return_value=reports) \
                as mock_get_file_reports:
            self.run_test(LookupHashesFilter, input_blobs=input_blobs, expected_output_blobs=output_blobs)
            mock_get_file_reports.assert_called_with(mock.ANY, [
                '6e87855371171d912dd866e8d7747bf965c80053f83259827a55826ca38a9360',
                'b779bafdf61b74784f2d3601ed663d7476da9ad4182601b8ca54fd4fbe1aa302'
            ])
