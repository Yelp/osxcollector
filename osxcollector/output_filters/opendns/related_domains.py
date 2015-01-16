# -*- coding: utf-8 -*-
#
# RelatedDomains uses OpenDNS to find domains related to input domains or ips and adds 'osxcollector_related' key when it finds them.
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.opendns.api import InvestigateApi
from osxcollector.output_filters.util.blacklist import create_blacklist
from osxcollector.output_filters.util.config import config_get_deep
from osxcollector.output_filters.util.domains import expand_domain


class RelatedDomainsFilter(OutputFilter):

    """Uses OpenDNS to find domains related to input domains or ips.

    A whitelist of domains to ignore is read during initialization.
    """

    def __init__(self, initial_domains=None, initial_ips=None, generations=2, related_when=None):
        """Initializes the RelatedDomainsFilter.

        Args:
            initial_domains: an enumerable of string domain names
            initial_ips: an enumerable of string IPs in the form ''
            generations: How many generations of related domains to retrieve. Passing 1
              means just find the domains related to the initial input. Passing 2 means also find the
              domains related to the domains related to the initial input.
            related_when: A boolean function to call to decide whether to add the domains from a line to
              the list of related domains.
        """
        super(RelatedDomainsFilter, self).__init__()
        self._whitelist = create_blacklist(config_get_deep('domain_whitelist'))

        cache_file_name = config_get_deep('opendns.RelatedDomainsFilter.cache_file_name', None)
        self._investigate = InvestigateApi(config_get_deep('api_key.opendns'), cache_file_name=cache_file_name)

        self._initial_domains = set(initial_domains) if initial_domains else set()
        self._initial_ips = set(initial_ips) if initial_ips else set()

        self._related_domains = set(initial_domains) if initial_domains else set()

        self._related_when = related_when
        self._generations = generations

        self._all_blobs = list()

    def filter_line(self, blob):
        """Accumulate a set of all domains.

        Args:
            blob: A dict representing one line of output from OSXCollector.
        Returns:
            A dict or None
        """
        self._all_blobs.append(blob)

        if 'osxcollector_domains' in blob and self._related_when and self._related_when(blob):
            for domain in blob.get('osxcollector_domains'):
                self._related_domains.add(domain)

        return None

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter performs any processing that requires the complete input to have already been fed.

        Returns:
            An enumerable of dicts
        """
        domains = self._initial_domains
        ips = self._initial_ips

        generations = self._generations
        while generations > 0:
            domains = self._find_related_domains(domains, ips)
            ips = None

            self._related_domains |= domains
            generations -= 1

        self._related_domains = filter(lambda x: not self._whitelist.match_values(x), list(self._related_domains))

        for blob in self._all_blobs:
            if self._related_domains and 'osxcollector_domains' in blob:
                for domain in blob.get('osxcollector_domains'):
                    if domain in self._related_domains:
                        blob.setdefault('osxcollector_related', {})
                        blob['osxcollector_related'].setdefault('domains', [])
                        blob['osxcollector_related']['domains'].append(domain)

        return self._all_blobs

    def _find_related_domains(self, domains, ips):
        related_domains = set()

        if domains:
            cooccurrence_info = self._investigate.cooccurrences(domains)
            related_domains.update(self._cooccurrences_to_domains(cooccurrence_info))

        if ips:
            rr_history_info = self._investigate.rr_history(ips)
            related_domains.update(self._rr_history_to_domains(rr_history_info))

        return related_domains

    def _cooccurrences_to_domains(self, cooccurrence_info):
        domains = []

        for cooccurence in cooccurrence_info:
            for occur_domain in cooccurence.get('pfs2', []):
                for elem in expand_domain(occur_domain[0]):
                    domains.add(elem)

        return domains

    def _rr_history_to_domains(self, rr_history_info):
        domains = []

        for rr_history in rr_history_info:
            for rr_domain in rr_history.get('rrs', []):
                for elem in expand_domain(rr_domain['rr']):
                    domains.add(elem)

        return domains


def main():
    run_filter(RelatedDomainsFilter())


if __name__ == "__main__":
    main()
