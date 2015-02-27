# -*- coding: utf-8 -*-
#
# Utilities for dealing with domain names
#
import re

import tldextract

from osxcollector.output_filters.exceptions import BadDomainError


def expand_domain(domain):
    """A generator that returns the input with and without the subdomain.

    Args:
        domain - string
    Returns:
        generator that returns strings
    """
    extraction = tldextract.extract(domain)

    if extraction.subdomain:
        subdomain = '.'.join(extraction)
        yield subdomain

    fulldomain = '.'.join(extraction[1:])
    yield fulldomain


def clean_domain(unclean_domain):
    """Removing errant characters and stuff from a domain name.

    A bit of careful dancing with character encodings. Eventually, some consumer of the domain string is gonna
    deal with it as ASCII. Make sure to encode as ASCII explicitly, so ASCII encoding errors can be ignored.

    Args:
        unclean_domain: string
    Returns:
        string domain name
    Raises:
        BadDomainError - when a clean domain can't be made
    """
    if not isinstance(unclean_domain, unicode):
        unclean_domain = unclean_domain.decode('utf-8', errors='ignore')

    unclean_domain = re.sub(r'^[^a-zA-Z0-9]*(.*?)[^a-zA-Z0-9]*$', r'\1', unclean_domain)

    extracted = tldextract.extract(unclean_domain)
    if bool(extracted.domain and extracted.suffix):
        start_index = 1 if not extracted.subdomain else 0
        domain = '.'.join(extracted[start_index:]).lstrip('.')
        return domain.encode('ascii', errors='ignore')

    raise BadDomainError(u'Can not clean {0} {1}'.format(unclean_domain, repr(extracted)))
