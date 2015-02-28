# -*- coding: utf-8 -*-
import testify as T

from osxcollector.output_filters.opendns.related_domains import RelatedDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class RelatedDomainsFilterTest(RunFilterTest):

    @T.setup
    def setupDomainsAndIPs(self):
        self._initial_domains = ['zendesk.com', 'jpmorganaccess.com', 'opendns.zendesk.com', 'yelp.com']
        self._initial_ips = ['159.53.60.177']

    def _run_test(self, input_blobs, expected_relateddomains):
        def create_filter():
            return RelatedDomainsFilter(initial_domains=self._initial_domains, initial_ips=self._initial_ips)
        output_blobs = self.run_test(create_filter, input_blobs=input_blobs)
        self.assert_key_added_to_blob('osxcollector_related', expected_relateddomains, input_blobs, output_blobs)

    def test_no_domains(self):
        input_blobs = [
            {'tater': 'tots'}
        ]
        expected_relateddomains = None
        self._run_test(input_blobs, expected_relateddomains)

    def test_direct_domain_match(self):
        # Direct meaning the domain in the input is an initial domain
        input_blobs = [
            {'osxcollector_domains': ['opendns.zendesk.com']}
        ]
        expected_relateddomains = [
            {
                'domains': {'opendns.zendesk.com': ['opendns.zendesk.com']}
            }
        ]
        self._run_test(input_blobs, expected_relateddomains)

    def test_related_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['webmd.com']}
        ]
        expected_relateddomains = [
            {
                'domains': {'webmd.com': ['opendns.zendesk.com', 'zendesk.com']}
            }
        ]
        self._run_test(input_blobs, expected_relateddomains)

    def test_multiple_related_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['webmd.com', 'hushmail.zendesk.com']}
        ]
        expected_relateddomains = [
            {
                'domains':
                {
                    'webmd.com': ['opendns.zendesk.com', 'zendesk.com'],
                    'hushmail.zendesk.com': ['opendns.zendesk.com']
                }
            }
        ]
        self._run_test(input_blobs, expected_relateddomains)

    def test_direct_and_related_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['zendesk.com']}
        ]
        expected_relateddomains = [
            {
                'domains': {'zendesk.com': ['opendns.zendesk.com', 'zendesk.com']}
            }
        ]
        self._run_test(input_blobs, expected_relateddomains)

    def test_direct_ip_match(self):
        input_blobs = [
            {'osxcollector_domains': ['jpmorganaccess.com']}
        ]
        expected_relateddomains = [
            {
                'domains': {'jpmorganaccess.com': ['159.53.60.177', 'jpmorganaccess.com', 'opendns.zendesk.com', 'zendesk.com']}
            }
        ]
        self._run_test(input_blobs, expected_relateddomains)

    def test_whitelist_domain(self):
        input_blobs = [
            {'osxcollector_domains': ['yelp.com']}
        ]
        expected_relateddomains = [
            None
        ]
        self._run_test(input_blobs, expected_relateddomains)
