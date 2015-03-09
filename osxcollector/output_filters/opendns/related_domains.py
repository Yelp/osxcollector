# -*- coding: utf-8 -*-
#
# RelatedDomains uses OpenDNS to find domains related to input domains or IPs.
# Adds 'osxcollector_related' key to the output:
# {
#    'osxcollector_related': {
#        'domains': {
#            'domain_in_line.com': ['related_domain.com'],
#            'another.com': ['1.2.3.4']
#        }
#     }
# }
#
from argparse import ArgumentParser

from threat_intel.opendns import InvestigateApi

from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main
from osxcollector.output_filters.util.blacklist import create_blacklist
from osxcollector.output_filters.util.config import config_get_deep
from osxcollector.output_filters.util.domains import expand_domain


DEFAULT_RELATED_DOMAINS_GENERATIONS = 2


class RelatedDomainsFilter(OutputFilter):

    """Uses OpenDNS to find domains related to input domains or IPs.

    A whitelist of domains to ignore is read during initialization.
    Adds 'osxcollector_related' key to the output:
    ```python
    {
       'osxcollector_related': {
           'domains': {
               'domain_in_line.com': ['related_domain.com'],
               'another.com': ['1.2.3.4']
           }
        }
    }
    ```
    """

    def __init__(self,
                 initial_domains=None,
                 initial_ips=None,
                 generations=DEFAULT_RELATED_DOMAINS_GENERATIONS,
                 related_when=None,
                 **kwargs):
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
        super(RelatedDomainsFilter, self).__init__(**kwargs)
        self._whitelist = create_blacklist(config_get_deep('domain_whitelist'))

        cache_file_name = config_get_deep('opendns.RelatedDomainsFilter.cache_file_name', None)
        self._investigate = InvestigateApi(config_get_deep('api_key.opendns'), cache_file_name=cache_file_name)

        self._domains_to_lookup = set(initial_domains) if initial_domains else set()
        self._ips_to_lookup = set(initial_ips) if initial_ips else set()

        self._related_when = related_when
        self._generation_count = generations

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
                self._domains_to_lookup.add(domain)

        return None

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter performs any processing that requires the complete input to have already been fed.

        Returns:
            An enumerable of dicts
        """
        domains_to_related = self._perform_lookup_for_all_domains(self._domains_to_lookup, self._ips_to_lookup)

        if domains_to_related:
            for blob in self._all_blobs:
                for domain in blob.get('osxcollector_domains', []):
                    add_related_domains = False
                    if domain in domains_to_related:
                        blob.setdefault('osxcollector_related', {})
                        blob['osxcollector_related'].setdefault('domains', {})
                        blob['osxcollector_related']['domains'].setdefault(domain, [])
                        blob['osxcollector_related']['domains'][domain] += domains_to_related[domain]
                        add_related_domains = True

                    # Unique the related domains
                    if add_related_domains:
                        blob['osxcollector_related']['domains'][domain] = list(set(blob['osxcollector_related']['domains'][domain]))

        return self._all_blobs

    def get_argument_parser(self):
        parser = ArgumentParser()
        group = parser.add_argument_group('opendns.RelatedDomainsFilter')
        group.add_argument('-d', '--domain', dest='initial_domains', default=[], action='append',
                           help='[OPTIONAL] Suspicious domains to use in pivoting.  May be specified more than once.')
        group.add_argument('-i', '--ip', dest='initial_ips', default=[], action='append',
                           help='[OPTIONAL] Suspicious IP to use in pivoting.  May be specified more than once.')
        group.add_argument('--related-domains-generations', dest='generations', default=DEFAULT_RELATED_DOMAINS_GENERATIONS,
                           help='[OPTIONAL] How many generations of related domains to lookup with OpenDNS')
        return parser

    def _filter_domains_by_whitelist(self, domains):
        """Remove all domains that are on the whitelist.

        Args:
            domains: An enumerable of domains
        Returns:
            An enumerable of domains
        """
        return filter(lambda x: not self._whitelist.match_values(x), list(domains))

    def _perform_lookup_for_all_domains(self, domains_to_lookup, ips_to_lookup):
        """Lookup all the domains related to the input domains or IPs.

        Args:
            domains_to_lookup: Enumerable of domains
            ips_to_lookup: Enumerable of IPs
        Returns:
            A dict mapping {'related_domain': ['initial_domainA', 'initial_domainB']}
        """
        self._domains_to_lookup = self._filter_domains_by_whitelist(self._domains_to_lookup)

        domains_to_related = {}

        what_to_lookup = [(domain, True) for domain in domains_to_lookup] + [(ip, False) for ip in ips_to_lookup]

        for domain_or_ip, is_domain in what_to_lookup:
            related_domains = self._perform_lookup_for_single_domain(domain_or_ip, is_domain, self._generation_count)
            related_domains = self._filter_domains_by_whitelist(related_domains)
            for related_domain in related_domains:
                domains_to_related.setdefault(related_domain, set())
                domains_to_related[related_domain].add(domain_or_ip)

        return domains_to_related

    def _perform_lookup_for_single_domain(self, domain_or_ip, is_domain, generation_count):
        """Given a domain or IP, lookup the Nth related domains.

        Args:
            domain_or_ip: A string domain name or IP
            is_domain: A boolean of whether the previous arg is a domain or IP
            generation_count: A count of generations to lookup
        Returns:
            set of related domains
        """
        domains_found = set([domain_or_ip]) if is_domain else set()
        generation_results = set([domain_or_ip])

        # For IPs, do one IP specific lookup then switch to domain lookups
        if not is_domain:
            generation_results = self._find_related_domains(None, generation_results)
            domains_found |= generation_results
            generation_count -= 1

        while generation_count > 0:
            if len(generation_results):
                generation_results = self._find_related_domains(generation_results, None)
                domains_found |= generation_results

            generation_count -= 1

        return domains_found

    def _find_related_domains(self, domains, ips):
        """Calls OpenDNS to find related domains and normalizes the responses.

        Args:
            domains: An enumerable of domains
            ips: An enumerable of IPs
        Returns:
            An enumerable of domains
        """
        related_domains = set()

        if domains:
            domains = self._filter_domains_by_whitelist(domains)
            cooccurrence_info = self._investigate.cooccurrences(domains)
            cooccurrence_domains = self._cooccurrences_to_domains(cooccurrence_info)
            related_domains.update(cooccurrence_domains)

        if ips:
            rr_history_info = self._investigate.rr_history(ips)
            related_domains.update(self._rr_history_to_domains(rr_history_info))

        return related_domains

    def _cooccurrences_to_domains(self, cooccurrence_info):
        """Parse the results of a call to the OpenDNS cooccurrences endpoint.

        Args:
            cooccurrence_info: Result of a call to cooccurrences
        Returns:
            An enumerable of domains
        """
        domains = set()

        for domain, cooccurence in cooccurrence_info.iteritems():
            for occur_domain in cooccurence.get('pfs2', []):
                for elem in expand_domain(occur_domain[0]):
                    domains.add(elem)

        return domains

    def _rr_history_to_domains(self, rr_history_info):
        """Parse the results of a call to the OpenDNS rr_history endpoint.

        Args:
            rr_history_info: Result of a call to rr_history
        Returns:
            An enumerable of domains
        """
        domains = set()

        for ip, rr_history in rr_history_info.iteritems():
            for rr_domain in rr_history.get('rrs', []):
                for elem in expand_domain(rr_domain['rr']):
                    domains.add(elem)

        return domains


def main():
    run_filter_main(RelatedDomainsFilter)


if __name__ == "__main__":
    main()
