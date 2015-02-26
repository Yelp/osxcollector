# -*- coding: utf-8 -*-
import testify as T

from osxcollector.output_filters.shadowserver.lookup_hashes import LookupHashesFilter
from tests.output_filters.run_filter_test import RunFilterTest


class LookupHashesFilterTest(RunFilterTest):

    @T.setup
    def setup_inputs(self):
        self._known_sha1_input = [
            {
                "sha2": "1fafe48f626fdc030b0a0efc1008d51cd3078d1b3ec95f808d12afbfef458b23",
                "sha1": "5d87de61cb368c93325dd910c202b8647f8e90ed",
                "ctime": "2014-12-05 16:50:48",
                "osxcollector_plist_path": "/System/Library/Extensions/System.kext/PlugIns/Libkern.kext/Info.plist",
                "mtime": "2014-09-19 00:42:35",
                "osxcollector_incident_id": "RecalibratedTurnip-2014_12_21-18_49_52",
                "osxcollector_section": "kext",
                "osxcollector_bundle_id": "com.apple.kpi.libkern",
                "file_path": "/System/Library/Extensions/System.kext/PlugIns/Libkern.kext/Libkern",
                "md5": "6746005c822ceb6737b871698d3ed22f"
            }
        ]
        self._unknown_sha1_input = [
            {
                "sha2": "5148211a7bc4a5d02913b0037805f20704f329e1739b5a6d2338fc84c1780b71",
                "sha1": "816a85d89ae34d2dc73b8c768eecb03935c568ba",
                "ctime": "2014-12-05 16:53:07",
                "osxcollector_plist_path": "/System/Library/Extensions/AMDRadeonX3000GLDriver.bundle/Contents/Info.plist",
                "mtime": "2014-09-28 22:34:42",
                "osxcollector_incident_id": "RecalibratedTurnip-2014_12_21-18_49_52",
                "osxcollector_section": "kext",
                "osxcollector_bundle_id": "com.apple.AMDRadeonX3000GLDriver",
                "file_path": "/System/Library/Extensions/AMDRadeonX3000GLDriver.bundle/Contents/MacOS/AMDRadeonX3000GLDriver",
                "md5": "967698d9ad4171bed991df85e1c72e56"
            }
        ]

    def test_no_match(self):
        output_blobs = self.run_test(LookupHashesFilter, self._unknown_sha1_input)
        T.assert_equal(1, len(output_blobs))

        T.assert_not_in('osxcollector_shadowserver', output_blobs[0])

    def test_known_match(self):
        output_blobs = self.run_test(LookupHashesFilter, self._known_sha1_input)
        T.assert_equal(1, len(output_blobs))

        T.assert_in('osxcollector_shadowserver', output_blobs[0])

    def test_known_match_different_path_prefix(self):
        self._known_sha1_input[0]['file_path'] = '/new_path/Libkern'
        output_blobs = self.run_test(LookupHashesFilter, self._known_sha1_input)
        T.assert_equal(1, len(output_blobs))

        T.assert_in('osxcollector_shadowserver', output_blobs[0])

    def test_wrong_filename(self):
        """Change the filename and don't match"""
        self._known_sha1_input[0]['file_path'] = 'wrong_name'
        output_blobs = self.run_test(LookupHashesFilter, self._known_sha1_input)
        T.assert_equal(1, len(output_blobs))

        T.assert_not_in('osxcollector_shadowserver', output_blobs[0])

    def test_partial_filename(self):
        """Change the filename and don't match"""
        self._known_sha1_input[0]['file_path'] = '/System/Library/Extensions/System.kext/PlugIns/Libkern.kext/Not_Quite_Libkern'
        output_blobs = self.run_test(LookupHashesFilter, self._known_sha1_input)
        T.assert_equal(1, len(output_blobs))

        T.assert_not_in('osxcollector_shadowserver', output_blobs[0])
