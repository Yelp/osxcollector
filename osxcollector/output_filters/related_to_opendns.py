# -*- coding: utf-8 -*-
import sys
import tldextract

# from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.opendns import Investigate
from osxcollector.output_filters.output_filter import OutputFilter


class RelatedToOpenDNS(OutputFilter):

    def __init__(self, initial_domains=None, initial_ips=None, depth=2):
        super(RelatedToOpenDNS, self).__init__()

        self._related_domains = set()

        # self._opendns = investigate.Investigate(self.get_config('api_key'))
        self._investigate = Investigate(self.get_config('api_key'))
        self._find_related_domains(initial_domains, initial_ips)
        while depth > 1:
            self._find_related_domains(self._related_domains, None)
            depth -= 1

        sys.stderr.write(repr(list(self._related_domains)))

    def _find_related_domains(self, initial_domains, initial_ips):
        new_domains = set()

        if initial_domains:
            for domain in initial_domains:
                cooccur = self._investigate.cooccurrences(domain)
                for occur in cooccur.get('pfs2', []):
                    for domain in self._extract_domains(occur[0]):
                        new_domains.add(domain)

        if initial_ips:
            for ip in initial_ips:
                history = self._investigate.rr_history(ip)
                for record in history.get('rrs', []):
                    for domain in self._extract_domains(record['rr']):
                        new_domains.add(domain)

        self._related_domains = self._related_domains.union(new_domains)

    def _extract_domains(self, value):
        extraction = tldextract.extract(value)
        if extraction.subdomain:
            yield '{0}.{1}.{2}'.format(extraction.subdomain, extraction.domain, extraction.suffix)
        yield '{0}.{1}'.format(extraction.domain, extraction.suffix)

    def filter_line(self, blob):
        if self._related_domains and 'osxcollector_domains' in blob:
            if any([domain in self._related_domains for domain in blob.get('osxcollector_domains')]):
                blob.setdefault('osxcollector_related', [])
                blob['osxcollector_related'].append('domains')

        return blob
        # return None
