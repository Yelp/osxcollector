#!/usr/bin/env python
# -*- coding: utf-8 -*-
import simplejson

from osxcollector.output_filters.blacklist import BlacklistFilter
from osxcollector.output_filters.chain import ChainFilter
from osxcollector.output_filters.chrome_history import ChromeHistoryFilter
from osxcollector.output_filters.domains import DomainsFilter
from osxcollector.output_filters.firefox_history import FirefoxHistoryFilter
from osxcollector.output_filters.opendns import OpenDNSFilter
from osxcollector.output_filters.output_filter import run_filter
from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.related_to_files import RelatedToFiles
from osxcollector.output_filters.virustotal_hashes import VTHashesFilter

from optparse import OptionParser


def is_suspicious(blob):
    return 'osxcollector_blacklist' in blob or 'osxcollector_related' in blob


def is_on_blacklist(blob):
    return 'osxcollector_blacklist' in blob


class _SummaryOutputFilter(OutputFilter):

    def __init__(self):
        super(_SummaryOutputFilter, self).__init__()
        self._all_blobs = list()

    def filter_line(self, blob):
        """Each Line of osxcollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swalling the line.

        Args:
            output_line: A dict

        Returns:
            A dict or None
        """
        self._all_blobs.append(blob)
        return None

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter can do any batch processing on that requires the complete input.

        Returns:
            An array of dicts (empty array if no lines remain)
        """
        with open('./suspicious.json', 'w') as fp:
            for blob in self._all_blobs:
                if is_suspicious(blob):
                    fp.write(simplejson.dumps(blob))
                    fp.write('\n')

        return self._all_blobs


class SummarizeFilter(ChainFilter):

    def __init__(self, initial_terms=None):
        filter_chain = [
            DomainsFilter(),
            BlacklistFilter(),
            RelatedToFiles(initial_terms=initial_terms, when=is_on_blacklist),
            OpenDNSFilter(is_suspicious_when=is_suspicious),
            # VTDomainsFilter(only_lookup_when=when_is_suspicious),
            VTHashesFilter(only_lookup_when=is_suspicious),
            FirefoxHistoryFilter(),
            ChromeHistoryFilter(),
            _SummaryOutputFilter()
        ]
        super(SummarizeFilter, self).__init__(filter_chain)


def main():
    parser = OptionParser(usage='usage: %prog [options]')
    parser.add_option('-t', '--term', dest='terms', default=[], action='append',
                      help='[OPTIONAL] Terms to search for.  May be specified more than once.')
    options, _ = parser.parse_args()

    run_filter(SummarizeFilter(initial_terms=options.terms))


if __name__ == "__main__":
    main()
