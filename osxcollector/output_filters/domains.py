#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# DomainsFilter looks for domains in all input lines and adds those domains into the 'osxcollector_domains' key.
#

import re
from urllib import unquote_plus
from urlparse import urlsplit

import tldextract
from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.output_filter import run_filter


class DomainsFilter(OutputFilter):

    """Adds 'osxcollector_domains' key to output lines.

    This filters parses domains out of anywhere in an output line and adds them to a clean array in the line.
    This is helpful as a pre-processing step before sending the domains off to threat APIs or matching against
    threat feeds.
    """

    def __init__(self):
        super(DomainsFilter, self).__init__()
        self._domains = set()

    def filter_line(self, blob):
        """Find domains in a line."""
        self._domains = set()
        self._look_for_domains(blob)

        # self._domains accumulates domains during calls to _look_for_domains
        if len(self._domains):
            blob['osxcollector_domains'] = list(self._domains)

        return blob

    def _look_for_domains(self, val, key=None):
        """Given a value and perhaps a key, look for domains.

        Args:
            val: The value, could be of any type
            key: A string key associated with the value.
        """
        if isinstance(val, basestring):
            if -1 != self.SCHEMES.search(val):
                # Sometimes values are complex strings, like JSON or pickle encoded stuff.
                # Try splitting the string on non-URL related punctuation
                for maybe_url in re.split('[ \'\(\)\"\[\]\{\}\;\n\t#@\^&\*=]+', val):
                    domain = self._url_to_domain(maybe_url)
                    if domain:
                        self._domains.add(domain)
            elif key in ['host', 'host_key']:
                domain = clean_domain(val)
                self._domains.add(domain)
        elif isinstance(val, list):
            for elem in val:
                self._look_for_domains(elem)
        elif isinstance(val, dict):
            for key, elem in val.iteritems():
                self._look_for_domains(elem, key)
                self._look_for_domains(key)

    def _url_to_domain(self, maybe_url):
        """Converts an URL to a domain.

        The code deals with ecentricities of both unquote_plus and split_url.

        Args:
            maybe_url - a string that might be an URL.
        Returns:
            a string representing the domain or None
        """
        if self.SCHEMES.match(maybe_url):
            url = unquote_plus(maybe_url).decode(encoding='utf-8', errors='ignore')

            split_url = urlsplit(url)
            if split_url.hostname:
                try:
                    return clean_domain(split_url.hostname)
                except BadDomainError:
                    pass

        return None

    SCHEMES = re.compile('((https?)|ftp)')


def clean_domain(unclean_domain):
    """Removing errant characters and stuff from a domain name.

    Args:
        unclean_domain: string
    Returns:
        string domain name
    Raises:
        BadDomainError - when a clean domain can't be made
    """
    extracted = tldextract.extract(unclean_domain)
    if extracted.domain and extracted.suffix:
        start_index = 1 if not extracted.subdomain else 0
        domain = '.'.join(extracted[start_index:]).lstrip('.')
        return domain
    raise BadDomainError('Can not clean {0}'.format(unclean_domain))


class BadDomainError(Exception):

    """An error to throw when a domain is invalid."""
    pass


def main():
    run_filter(DomainsFilter())


if __name__ == "__main__":
    main()
