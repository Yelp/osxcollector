# -*- coding: utf-8 -*-
#
# RelatedDomains uses OpenDNS to find domains related to input domains or ips and adds 'osxcollector_related' key when it finds them.
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.opendns.api import InvestigateApi


class RelatedDomainsFilter(OutputFilter):

    """Uses OpenDNS to find domains related to input domains or ips."""

    def __init__(self, initial_domains=None, initial_ips=None, depth=2):
        super(RelatedDomainsFilter, self).__init__()
        self._investigate = InvestigateApi(self.config.get_config('api_key.opendns'))

        initial_domains = initial_domains or []
        initial_ips = initial_ips or []

        self._related_domains = set(initial_domains)

        domains = initial_domains
        ips = initial_ips

        while depth > 0:
            domains = self._find_related_domains(domains, ips)
            ips = None

            self._related_domains |= domains
            depth -= 1

    def _find_related_domains(self, domains, ips):
        related_domains = set()

        if domains:
            related_domains.update(self._investigate.cooccurrences(domains))

        if ips:
            related_domains.update(self._investigate.rr_history(ips))

        return related_domains

    def filter_line(self, blob):
        if self._related_domains and 'osxcollector_domains' in blob:
            if any([domain in self._related_domains for domain in blob.get('osxcollector_domains')]):
                blob.setdefault('osxcollector_related', [])
                blob['osxcollector_related'].append('domains')

        return blob


def main():
    run_filter(RelatedDomainsFilter())


if __name__ == "__main__":
    main()
