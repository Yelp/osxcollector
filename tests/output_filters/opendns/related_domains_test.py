# -*- coding: utf-8 -*-
import testify as T

from osxcollector.output_filters.opendns.related_domains import RelatedDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class RelatedDomainsFilterTest(RunFilterTest):

    @T.setup
    def setupInput(self):
        self.input_blobs = [
            {
                'expires_utc': 0,
                'host_key': 'opendns.zendesk.com',
                'osxcollector_username': 'ivanlei',
                'name': '_zendesk_session',
                'encrypted_value': '<read-write buffer ptr 0x7f94b4083880, size 371 at 0x7f94b4083840>',
                'persistent': 0,
                'value': '',
                'priority': 1,
                'osxcollector_section': 'chrome',
                'osxcollector_subsection': 'cookies',
                'last_access_utc': '2015-02-24 10:54:14',
                'osxcollector_incident_id': 'chrome-2015_02_26-10_44_25',
                'path': '/',
                'has_expires': 0,
                'osxcollector_table_name': 'cookies',
                'creation_utc': '2015-02-24 10:54:14',
                'osxcollector_db_path': '/Users/ivanlei/Library/Application Support/Google/Chrome/Default/Cookies',
                'httponly': 1,
                'secure': 1,
                'osxcollector_domains': ['opendns.zendesk.com', 'zendesk.com']
            }
        ]
        self._initial_domains = ['zendesk.com']

    def _run_test(self, expected_relateddomains):
        output_blobs = self.run_test(lambda: RelatedDomainsFilter(self._initial_domains), input_blobs=self.input_blobs)
        self.assert_key_added_to_blob('osxcollector_related', expected_relateddomains, self.input_blobs, output_blobs)

    def test_no_domains(self):
        del self.input_blobs[0]['osxcollector_domains']
        expected_relateddomains = None
        self._run_test(expected_relateddomains)

    def test_domain(self):
        expected_relateddomains = [
            {'domains': ['zendesk.com']}
        ]
        self._run_test(expected_relateddomains)
