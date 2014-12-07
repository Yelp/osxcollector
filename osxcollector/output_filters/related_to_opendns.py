# -*- coding: utf-8 -*-
#
# RelatedToOpenDNSFilter uses OpenDNS to find domains related to input domains or ips.
#
import sys

from osxcollector.output_filters.opendns import Investigate
from osxcollector.output_filters.output_filter import OutputFilter


class RelatedToOpenDNSFilter(OutputFilter):

    """Uses OpenDNS to find domains related to input domains or ips."""

    def __init__(self, initial_domains=None, initial_ips=None, depth=1):
        super(RelatedToOpenDNSFilter, self).__init__()
        self._investigate = Investigate(self.config.get_config('api_key.opendns'))

        initial_domains = initial_domains or []
        initial_ips = initial_ips or []

        self._related_domains = set(initial_domains)

        domains = initial_domains
        ips = initial_ips

        while depth > 0:
            domains = self._find_related_domains(domains, ips)
            sys.stderr.write(repr(list(domains)))
            ips = None

            sys.stderr.write('+' + repr(list(domains)) + '\n')
            self._related_domains |= domains
            sys.stderr.write('-' + repr(list(domains)) + '\n')
            depth -= 1

        sys.stderr.write('*' + repr(list(self._related_domains)) + '\n')

    def _find_related_domains(self, domains, ips):
        related_domains = set()

        if domains:
            for domain in self._investigate.cooccurrences(domains):
                related_domains.add(domain)

        if ips:
            for domain in self._investigate.rr_history(ips):
                sys.stderr.write('{0}\n'.format(domain))
                related_domains.add(domain)

        return related_domains

    def filter_line(self, blob):
        if self._related_domains and 'osxcollector_domains' in blob:
            if any([domain in self._related_domains for domain in blob.get('osxcollector_domains')]):
                blob.setdefault('osxcollector_related', [])
                blob['osxcollector_related'].append('domains')

        return blob
