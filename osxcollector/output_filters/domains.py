#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import simplejson
import sys
from urlparse import urlsplit
from urllib import unquote_plus

from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.output_filter import run_filter

class DomainsFilter(OutputFilter):
    """Adds 'osxcollector_domains' key to output lines.

    This filters parses domains out of anywhere in an output line and adds them to a clean array in the line.
    This is helpful as a pre-processing step before sending the domains off to threat APIs or matching against
    threat feeds.
    """
    def __init__(self):
        self._domains = set()

    def filter_line(self, line):
        """Find domains in a line."""
        try:
            blob = simplejson.loads(line)
            self._domains = set()
        except:
            return line

        self._look_for_domains(blob)

        # self._domains accumulates domains during calls to _look_for_domains
        if len(self._domains):
            blob['osxcollector_domains'] = list(self._domains)
            line = '{0}\n'.format(simplejson.dumps(blob))

        return line

    def _look_for_domains(self, val, key=None):
        """Given a value and perhaps a key, look for domains.

        Args:
            val: The value, could be of any type
            key: A string key associated with the value.
        """
        if isinstance(val, basestring):
            if -1 == val.find('http'):
                return

            # Sometimes values are complex strings, like JSON or pickle encoded stuff.
            # Try splitting the string on non-URL related punctuation
            for part in re.split('[ \'\(\)\"\[\]\{\}\;\n\t]+', val):
                if part.startswith('http'):
                    self._add_domain(part)
        elif isinstance(val, list):
            for elem in val:
                self._look_for_domains(elem)
        elif isinstance(val, dict):
            for key, elem in val.iteritems():
                self._look_for_domains(elem)

    def _add_domain(self, val):
        """Accumulates domain names in self._domains

        The code deals with ecentricities of both unquote_plus and split_url
        """
        try:
            url = unquote_plus(val).decode(encoding='utf-8', errors='ignore')
        except:
            # In the case that a substring can't be unquoted, the potential domain is lost
            return

        split_url = urlsplit(url)
        if split_url.hostname:
            domain = split_url.hostname.split('\\')[-1].rstrip('.').lstrip('.')
            if -1 != domain.find('.'):
                self._domains.add(domain)


def main():
    run_filter(DomainsFilter())


if __name__ == "__main__":
    main()