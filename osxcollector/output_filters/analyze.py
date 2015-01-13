#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# The AnalyzeFilter is a handy little tool that ties together many filters to attempt to
# enhance the output of OSXCollector with data from threat APIs, compare against blacklists,
# search for lines related to suspicious domains, ips, or files, and generally figure shit out.
#
# The more detailed description of what goes on:
#  1. Find all the domains in every line. Add them to the output lines.
#  2. Find any file hashes or domains that are on blacklists. Mark those lines.
#  3. Take any filepaths from the command line and mark all lines related to those.
#  4. Take any domain or IP from the command line and use OpenDNS Investigate API to find all the domains
#     related to those domains and all the domains related to those related domains - basically the 1st and 2nd
#     generation related domains. Mark any lines where these domains appear.
#  5. Lookup all sha1 hashes in ShadowServer's bin-test whitelist. Files that match both hash and filename are ignored by further filters.
#  6. Lookup file hashes in VirusTotal and mark any lines with suspicious files hashes.
#  7. Lookup all the domains in the file with OpenDNS Investigate. Categorize and score the domains.
#     Mark all the lines that contain domains that were scored as "suspicious".
#  8. Lookup suspicious domains, those domains on a blacklist, or those related to the initial input in VirusTotal.
#  9. Cleanup the browser history and sort it in descending time order.
# 10. Save all the enhanced output to a new file.
# 11. Look at all the interesting lines in the file and try to summarize them in some very human readable output.
# 12. Party!
#
import sys
from argparse import ArgumentParser
from numbers import Number

import simplejson
from osxcollector.output_filters.base_filters.chain import ChainFilter
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.chrome_history import ChromeHistoryFilter
from osxcollector.output_filters.find_blacklisted import FindBlacklistedFilter
from osxcollector.output_filters.find_domains import FindDomainsFilter
from osxcollector.output_filters.firefox_history import FirefoxHistoryFilter
from osxcollector.output_filters.opendns. \
    lookup_domains import LookupDomainsFilter as OpenDnsLookupDomainsFilter
from osxcollector.output_filters.opendns. \
    related_domains import RelatedDomainsFilter as OpenDnsRelatedDomainsFilter
from osxcollector.output_filters.related_files import RelatedFilesFilter
from osxcollector.output_filters.shadowserver. \
    lookup_hashes import LookupHashesFilter as ShadowServerLookupHashesFilter
from osxcollector.output_filters.virustotal. \
    lookup_domains import LookupDomainsFilter as VtLookupDomainsFilter
from osxcollector.output_filters.virustotal. \
    lookup_hashes import LookupHashesFilter as VtLookupHashesFilter

DEFAULT_RELATED_DOMAINS_GENERATIONS = 2


class AnalyzeFilter(ChainFilter):

    """AnalyzeFilter chains all the other filters to produce maximum effect.

    A lot of the smarts of AnalyzeFilter are around what filters to run in which order and how results of one filter should
    effect the operations of the next filter.
    """

    def __init__(self,
                 initial_file_terms=None,
                 initial_domains=None,
                 initial_ips=None,
                 related_domains_generations=DEFAULT_RELATED_DOMAINS_GENERATIONS,
                 monochrome=False,
                 no_shadowserver=False,
                 no_opendns=False,
                 no_virustotal=False
                 ):

        filter_chain = []

        filter_chain.append(FindDomainsFilter())

        # Do hash related lookups first. This is done first since hash lookup is not influenced
        # by anything but other hash lookups.
        if not no_shadowserver:
            filter_chain.append(ShadowServerLookupHashesFilter())
        if not no_virustotal:
            filter_chain.append(VtLookupHashesFilter(lookup_when=lookup_when_not_in_shadowserver))

        # Find blacklisted stuff next. Finding blacklisted domains requires running FindDomainsFilter first.
        filter_chain.append(FindBlacklistedFilter())

        # RelatedFilesFilter and OpenDnsRelatedDomainsFilter use command line args in addition to previous filter results to find
        # lines of interest.
        filter_chain.append(RelatedFilesFilter(initial_terms=initial_file_terms, when=find_related_when))
        if not no_opendns:
            filter_chain.append(OpenDnsRelatedDomainsFilter(initial_domains=initial_domains,
                                                            initial_ips=initial_ips, related_when=find_related_when,
                                                            generations=related_domains_generations))

        # Lookup threat info on suspicious and related stuff
        if not no_virustotal:
            filter_chain.append(OpenDnsLookupDomainsFilter(lookup_when=lookup_when_not_in_shadowserver))
        if not no_opendns:
            filter_chain.append(VtLookupDomainsFilter(lookup_when=lookup_domains_in_vt_when))

        # Sort browser history for maximum pretty
        filter_chain.append(FirefoxHistoryFilter())
        filter_chain.append(ChromeHistoryFilter())

        # Summarize what has happened
        filter_chain.append(_OutputToFileFilter())
        filter_chain.append(_VeryReadableOutputFilter(monochrome=monochrome))

        super(AnalyzeFilter, self).__init__(filter_chain)


def include_in_summary(blob):
    _KEYS_FOR_SUMMARY = [
        'osxcollector_vthash',
        'osxcollector_vtdomain',
        'osxcollector_opendns',
        'osxcollector_blacklist',
        'osxcollector_related'
    ]

    return any([key in blob for key in _KEYS_FOR_SUMMARY])


def lookup_when_not_in_shadowserver(blob):
    """ShadowServer whitelists blobs that can be ignored."""
    return 'osxcollector_shadowserver' not in blob


def lookup_domains_in_vt_when(blob):
    """VT domain lookup is a final step and what to lookup is dependent upon what has been found so far."""
    return lookup_when_not_in_shadowserver(blob) and include_in_summary(blob)


def find_related_when(blob):
    """When to find related terms or domains.

    Stuff in ShadowServer is not interesting.
    Blacklisted file paths are worth investigating.
    Files where the md5 could not be calculated are also interesting. Root should be able to read files.
    Files with a bad hash in VT are obviously malware, go find related bad stuff.

    Args:
        blob - a line of output from OSXCollector
    Returns:
        boolean
    """
    if 'osxcollector_shadowserver' in blob:
        return False
    if '' == blob.get('md5', None):
        return True
    return any([key in blob for key in ['osxcollector_vthash', 'osxcollector_related']])


class _OutputToFileFilter(OutputFilter):

    def __init__(self):
        super(_OutputToFileFilter, self).__init__()
        self._all_blobs = list()

    def filter_line(self, blob):
        """Each Line of OSXCollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swallowing the line.

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
        if len(self._all_blobs):
            incident_id = self._all_blobs[0]['osxcollector_incident_id']

            with open('./analyze_{0}.json'.format(incident_id), 'w') as fp:
                for blob in self._all_blobs:
                    fp.write(simplejson.dumps(blob))
                    fp.write('\n')

        return self._all_blobs


class _VeryReadableOutputFilter(OutputFilter):

    def __init__(self, monochrome=False):
        super(_VeryReadableOutputFilter, self).__init__()
        self._vthash = []
        self._vtdomain = []
        self._opendns = []
        self._blacklist = []
        self._related = []
        self._monochrome = monochrome
        self._add_to_blacklist = []

    def filter_line(self, blob):
        """Each Line of OSXCollector output will be passed to filter_line.

        The OutputFilter should return the line, either modified or unmodified.
        The OutputFilter can also choose to return nothing, effectively swallowing the line.

        Args:
            output_line: A dict

        Returns:
            A dict or None
        """
        if 'osxcollector_vthash' in blob:
            self._vthash.append(blob)
        if 'osxcollector_vtdomain' in blob:
            self._vtdomain.append(blob)
        if 'osxcollector_opendns' in blob:
            self._opendns.append(blob)
        if 'osxcollector_blacklist' in blob:
            self._blacklist.append(blob)
        if 'osxcollector_related' in blob:
            self._related.append(blob)

        return None

    END_COLOR = '\033[0m'
    SECTION_COLOR = '\033[1m'
    BOT_COLOR = '\033[93m\033[1m'
    KEY_COLOR = '\033[94m'
    VAL_COLOR = '\033[32m'

    def _write(self, msg, color=END_COLOR):
        if not self._monochrome:
            sys.stdout.write(color)
        sys.stdout.write(msg)
        if not self._monochrome:
            sys.stdout.write(self.END_COLOR)

    def end_of_lines(self):
        """Called after all lines have been fed to filter_output_line.

        The OutputFilter can do any batch processing on that requires the complete input.

        Returns:
            An array of dicts (empty array if no lines remain)
        """
        self._write('== Very Readable Output Bot ==\n', self.BOT_COLOR)
        self._write('Let\'s see what\'s up with this machine.\n\n', self.BOT_COLOR)

        if len(self._vthash):
            self._write('Dang! You\'ve got known malware on this machine. Hope it\'s commodity stuff\n', self.BOT_COLOR)
            self._summarize_blobs(self._vthash)
            self._write('Sheesh! This is why we can\'t have nice things!\n\n', self.BOT_COLOR)

        if len(self._vtdomain):
            self._write('I see you\'ve been visiting some \'questionable\' sites. If you trust VirusTotal that is.\n', self.BOT_COLOR)
            self._summarize_blobs(self._vtdomain)
            self._write('I hope it was worth it!\n\n', self.BOT_COLOR)

        if len(self._opendns):
            self._write('Well, here\'s some domains OpenDNS wouldn\'t recommend.\n', self.BOT_COLOR)
            self._summarize_blobs(self._opendns)
            self._write('You know you shouldn\'t just click every link you see? #truth\n\n', self.BOT_COLOR)

        if len(self._blacklist):
            self._write('We put stuff on a blacklist for a reason. Mostly so you don\'t do this.\n', self.BOT_COLOR)
            self._summarize_blobs(self._blacklist)
            self._write('SMH\n\n', self.BOT_COLOR)

        if len(self._related):
            self._write('This whole things started with just a few clues. Now look what I found.\n', self.BOT_COLOR)
            self._summarize_blobs(self._related)
            self._write('Nothing hides from Very Readable Output Bot\n\n', self.BOT_COLOR)

        if len(self._add_to_blacklist):
            self._add_to_blacklist = list(set(self._add_to_blacklist))
            self._write('If I were you, I\'d probably update my blacklists to include:\n', self.BOT_COLOR)
            for key, val in self._add_to_blacklist:
                self._summarize_val(key, val)
            self._write('That might just help things, Skippy!\n\n', self.BOT_COLOR)

        self._write('== Very Readable Output Bot ==\n', self.BOT_COLOR)
        self._write('#kaythanksbye', self.BOT_COLOR)

        return []

    def _summarize_blobs(self, blobs):
        for blob in blobs:
            self._summarize_line(blob)

            add_to_blacklist = False

            if 'osxcollector_vthash' in blob:
                self._summarize_vthash(blob)
                add_to_blacklist = True

            if 'osxcollector_vtdomain' in blob:
                self._summarize_vtdomain(blob)

            if 'osxcollector_opendns' in blob:
                self._summarize_opendns(blob)

            if 'osxcollector_blacklist' in blob:
                for key in blob['osxcollector_blacklist'].keys():
                    self._summarize_val('blacklist-{0}'.format(key), blob['osxcollector_blacklist'][key])

            if 'osxcollector_related' in blob:
                for key in blob['osxcollector_related'].keys():
                    self._summarize_val('related-{0}'.format(key), blob['osxcollector_related'][key])

            if 'md5' in blob and '' == blob['md5']:
                add_to_blacklist = True

            if add_to_blacklist:
                blacklists = blob.get('osxcollector_blacklist', {})
                values_on_blacklist = blacklists.get('hashes', [])
                for key in ['md5', 'sha1', 'sha2']:
                    val = blob.get(key, '')
                    if len(val) and val not in values_on_blacklist:
                        self._add_to_blacklist.append((key, val))

                values_on_blacklist = blacklists.get('domains', [])
                for domain in blob.get('osxcollector_domains', []):
                    if domain not in values_on_blacklist:
                        self._add_to_blacklist.append(('domain', domain))

    def _summarize_line(self, blob):
        section = blob.get('osxcollector_section')
        subsection = blob.get('osxcollector_subsection', '')

        self._write('- {0} {1}\n'.format(section, subsection), self.SECTION_COLOR)
        for key in sorted(blob.keys()):
            if not key.startswith('osxcollector') and blob.get(key):
                val = blob.get(key)
                self._summarize_val(key, val)

    def _summarize_vthash(self, blob):
        for blob in blob['osxcollector_vthash']:
            for key in ['positives', 'total', 'scan_date', 'permalink']:
                val = blob.get(key)
                self._summarize_val(key, val, 'vthash')

    def _summarize_vtdomain(self, blob):
        for blob in blob['osxcollector_vtdomain']:
            for key in ['domain', 'detections']:
                val = blob.get(key)
                self._summarize_val(key, val, 'vtdomain')

    def _summarize_opendns(self, blob):
        for blob in blob['osxcollector_opendns']:
            for key in ['domain', 'categorization', 'security', 'link']:
                val = blob.get(key)
                self._summarize_val(key, val, 'opendns')

    def _summarize_val(self, key, val, prefix=None):
        self._print_key(key, prefix)
        self._print_val(val)
        self._write('\n')

    def _print_key(self, key, prefix):
        if not prefix:
            prefix = ''
        else:
            prefix += '-'

        self._write('  {0}{1}'.format(prefix, key), self.KEY_COLOR)
        self._write(': ')

    def _print_val(self, val):
        if isinstance(val, list):
            self._write('[')
            for index, elem in enumerate(val):
                self._print_val(elem)
                if index != len(val) - 1:
                    self._write(', ')
            self._write(']')
        elif isinstance(val, dict):
            self._write('{')
            keys = val.keys()
            for index, key in enumerate(keys):
                self._write('"')
                self._write(key, self.VAL_COLOR)
                self._write('": ')
                self._print_val(val[key])
                if index != len(keys) - 1:
                    self._write(', ')
            self._write('}')
        elif isinstance(val, basestring):
            val = val[:480]
            self._write('"')
            self._write(val, self.VAL_COLOR)
            self._write('"')
        elif isinstance(val, Number):
            self._write('{0}'.format(val), self.VAL_COLOR)


def main():
    parser = ArgumentParser()
    parser.add_argument('-f', '--file-term', dest='file_terms', default=[], action='append',
                        help='[OPTIONAL] Suspicious terms to use in pivoting through file names.  May be specified more than once.')
    parser.add_argument('-d', '--domain', dest='domain_terms', default=[], action='append',
                        help='[OPTIONAL] Suspicious domains to use for pivoting.  May be specified more than once.')
    parser.add_argument('-i', '--ip', dest='ip_terms', default=[], action='append',
                        help='[OPTIONAL] Suspicious IP to use for pivoting.  May be specified more than once.')
    parser.add_argument('--related-domains-generations', dest='related_domains_generations', default=DEFAULT_RELATED_DOMAINS_GENERATIONS,
                        help='[OPTIONAL] How many generations of related domains to lookup with OpenDNS')
    parser.add_argument('--readout', dest='readout', action='store_true', default=False,
                        help='[OPTIONAL] Skip the analysis and just output really readable analysis')
    parser.add_argument('-M', '--monochrome', dest='monochrome', action='store_true', default=False,
                        help='[OPTIONAL] Output monochrome analysis')
    parser.add_argument('--no-opendns', dest='no_opendns', action='store_true', default=False,
                        help='[OPTIONAL] Don\'t run OpenDNS filters')
    parser.add_argument('--no-virustotal', dest='no_virustotal', action='store_true', default=False,
                        help='[OPTIONAL] Don\'t run VirusTotal filters')
    parser.add_argument('--no-shadowserver', dest='no_shadowserver', action='store_true', default=False,
                        help='[OPTIONAL] Don\'t run ShadowServer filters')
    parser.add_argument('--input-file', dest='input_file', default=None,
                        help='[OPTIONAL] Path to OSXCollector output to read. Defaults to stdin otherwise.')

    args = parser.parse_args()

    if not args.readout:
        output_filter = AnalyzeFilter(initial_file_terms=args.file_terms, initial_domains=args.domain_terms,
                                      initial_ips=args.ip_terms, related_domains_generations=args.related_domains_generations,
                                      monochrome=args.monochrome, no_opendns=args.no_opendns, no_virustotal=args.no_virustotal,
                                      no_shadowserver=args.no_shadowserver)
    else:
        output_filter = _VeryReadableOutputFilter(monochrome=args.monochrome)

    if args.input_file:
        with(open(args.input_file, 'r')) as fp_in:
            run_filter(output_filter, input_stream=fp_in)
    else:
        run_filter(output_filter)

if __name__ == "__main__":
    main()
