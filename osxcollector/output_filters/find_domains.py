#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# FindDomainsFilter looks for domains in all input lines and adds those domains into the 'osxcollector_domains' key.
#
import re
from urllib import unquote_plus
from urlparse import urlsplit

from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter
from osxcollector.output_filters.exceptions import BadDomainError
from osxcollector.output_filters.util.domains import clean_domain
from osxcollector.output_filters.util.domains import expand_domain


class FindDomainsFilter(OutputFilter):

    """Adds 'osxcollector_domains' key to output lines.

    This filters parses domains out of anywhere in an output line and adds them to a clean array in the line.
    This is helpful as a pre-processing step before sending the domains off to threat APIs or matching against
    threat feeds.
    """

    def __init__(self):
        super(FindDomainsFilter, self).__init__()
        self._domains = set()

    def filter_line(self, blob):
        """Find domains in a line."""
        self._domains = set()
        self._look_for_domains(blob)

        # self._domains accumulates domains during calls to _look_for_domains
        if len(self._domains):
            blob['osxcollector_domains'] = sorted(list(self._domains))

        return blob

    def _look_for_domains(self, val, key=None):
        """Given a value and perhaps a key, look for domains.

        Args:
            val: The value, could be of any type
            key: A string key associated with the value.
        """
        if isinstance(val, basestring):
            if key in self.HOST_KEYS:
                self._add_domain(val)
                return
            if -1 != self.SCHEMES.search(val):
                # Sometimes values are complex strings, like JSON or pickle encoded stuff.
                # Try splitting the string on non-URL related punctuation
                for maybe_url in re.split('[ \'\(\)\"\[\]\{\}\;\n\t#@\^&\*=]+', val):
                    domain = self._url_to_domain(maybe_url)
                    self._add_domain(domain)
        elif isinstance(val, list):
            for elem in val:
                self._look_for_domains(elem)
        elif isinstance(val, dict):
            for key, elem in val.iteritems():
                self._look_for_domains(elem, key)
                self._look_for_domains(key)

    def _url_to_domain(self, maybe_url):
        """Converts an URL to a domain.

        The code deals with eccentricities of both unquote_plus and split_url.

        Args:
            maybe_url - a string that might be an URL.
        Returns:
            a string representing the domain or None
        """
        if self.SCHEMES.match(maybe_url):
            url = unquote_plus(maybe_url)

            split_url = urlsplit(url)
            if split_url.hostname:
                return split_url.hostname

        return None

    def _add_domain(self, domain):
        """Clean a domain and store it internally"""
        if not domain:
            return

        try:
            domain = clean_domain(domain)
            for extracted in expand_domain(domain):
                self._domains.add(extracted)
        except BadDomainError:
            pass

    SCHEMES = re.compile('((https?)|ftp)')
    HOST_KEYS = ['host', 'host_key', 'baseDomain']


def main():
    run_filter(FindDomainsFilter())


if __name__ == "__main__":
    main()
