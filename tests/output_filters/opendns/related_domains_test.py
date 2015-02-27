# -*- coding: utf-8 -*-
from osxcollector.output_filters.opendns.related_domains import RelatedDomainsFilter
from tests.output_filters.run_filter_test import RunFilterTest


class RelatedDomainsFilterTest(RunFilterTest):

    def _run_test(self, input_blobs, initial_domains, initial_ips, expected_relateddomains):
        def create_filter():
            return RelatedDomainsFilter(initial_domains=initial_domains, initial_ips=initial_ips)
        output_blobs = self.run_test(create_filter, input_blobs=input_blobs)
        self.assert_key_added_to_blob('osxcollector_related', expected_relateddomains, input_blobs, output_blobs)

    def test_no_domains(self):
        input_blobs = [
            {'tater': 'tots'}
        ]
        expected_relateddomains = None
        initial_domains = ['zendesk.com']
        self._run_test(input_blobs, initial_domains, None, expected_relateddomains)

    def test_direct_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['opendns.zendesk.com', 'zendesk.com']}
        ]
        expected_relateddomains = [
            {'domains': ['zendesk.com']}
        ]
        initial_domains = ['zendesk.com']
        self._run_test(input_blobs, initial_domains, None, expected_relateddomains)

    def test_indirect_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['jpmorganaccess.com']}
        ]
        expected_relateddomains = [
            {'domains': ['zendesk.com']}
        ]
        initial_domains = ['zendesk.com']
        self._run_test(input_blobs, initial_domains, None, expected_relateddomains)

    def test_multiple_indirect_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['zdnscloud.com', 'jpmorganaccess.com']}
        ]
        expected_relateddomains = [
            {'domains': ['zendesk.com']}
        ]
        initial_domains = ['zendesk.com']
        self._run_test(input_blobs, initial_domains, None, expected_relateddomains)

    def test_multiple_direct_domain_match(self):
        input_blobs = [
            {'osxcollector_domains': ['opendns.zendesk.com', 'zendesk.com']}
        ]
        expected_relateddomains = [
            {'domains': ['opendns.zendesk.com', 'zendesk.com']}
        ]
        initial_domains = ['opendns.zendesk.com', 'zendesk.com']
        self._run_test(input_blobs, initial_domains, None, expected_relateddomains)

    def test_indirect_ip_match(self):
        input_blobs = [
            {'osxcollector_domains': ['www.marketwatch.com']}
        ]
        expected_relateddomains = [
            {'domains': ['159.53.60.177']}
        ]
        initial_ips = ['159.53.60.177']
        self._run_test(input_blobs, None, initial_ips, expected_relateddomains)
