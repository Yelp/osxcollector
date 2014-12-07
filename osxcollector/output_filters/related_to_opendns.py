# -*- coding: utf-8 -*-
from osxcollector.output_filters.opendns import Investigate
from osxcollector.output_filters.output_filter import OutputFilter


# from osxcollector.osxcollector import DictUtils


class RelatedToOpenDNSFilter(OutputFilter):

    def __init__(self, initial_domains=None, initial_ips=None, depth=1):
        super(RelatedToOpenDNSFilter, self).__init__()
        self._investigate = Investigate(self.get_config('api_key'))

        self._related_domains = set()
        self._related_domains.union(initial_domains)

        domains = initial_domains
        ips = initial_ips

        while depth > 0:
            domains = self._find_related_domains(domains, ips)
            ips = None

            self._related_domains.union(domains)
            depth -= 1

    def _find_related_domains(self, initial_domains, initial_ips):
        related_domains = set()
        if initial_domains:
            related_domains.union(self._investigate.cooccurrences(initial_domains))

        if initial_ips:
            related_domains.union(self._investigate.rr_history(initial_domains))

        return related_domains

    def filter_line(self, blob):
        if self._related_domains and 'osxcollector_domains' in blob:
            if any([domain in self._related_domains for domain in blob.get('osxcollector_domains')]):
                blob.setdefault('osxcollector_related', [])
                blob['osxcollector_related'].append('domains')

        return blob
