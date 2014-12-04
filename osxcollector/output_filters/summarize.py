#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import simplejson
import sys

from osxcollector.osxcollector import DictUtils

from osxcollector.output_filters.blacklist import BlacklistFilter
from osxcollector.output_filters.chain import ChainFilter
from osxcollector.output_filters.chrome_history import ChromeHistoryFilter
from osxcollector.output_filters.domains import DomainsFilter
from osxcollector.output_filters.firefox_history import FirefoxHistoryFilter
from osxcollector.output_filters.opendns import OpenDNSFilter
from osxcollector.output_filters.output_filter import MissingConfigError
from osxcollector.output_filters.output_filter import run_filter
from osxcollector.output_filters.virustotal_domains import VTDomainsFilter
from osxcollector.output_filters.virustotal_hashes import VTHashesFilter


class SummarizeFilter(ChainFilter):

    def __init__(self):
        # def when_blacklist(blob):
        #     return 'osxcollector_blacklist' in blob

        # def when_suspicious(blob): 
        #     return 'osxcollector_opendns' in blob or 'osxcollector_blacklist' in blob

        def is_suspicious_when_on_blacklist(blob):
            return 'osxcollector_blacklist' in blob

        filter_chain = [
            DomainsFilter(),
            BlacklistFilter(),
            FirefoxHistoryFilter(),
            ChromeHistoryFilter(),
            OpenDNSFilter(is_suspicious_when=is_suspicious_when_on_blacklist)#only_lookup_when=when_blacklist)
            #VTDomainsFilter(when=when_suspicious),
            #VTHashesFilter(when=when_suspicious),
        ]
        super(SummarizeFilter, self).__init__(filter_chain)


def main():
    run_filter(SummarizeFilter())


if __name__ == "__main__":
    main()
