# -*- coding: utf-8 -*-
#
# Utilities for dealing with domain names
#
import tldextract
from osxcollector.output_filters.exceptions import BadDomainError


def expand_domain(domain):
    """A generator that returns the input with and without the subdomain

    Args:
        domain - string
    Returns:
        generator that returns strings
    """
    extraction = tldextract.extract(domain)
    if extraction.subdomain:
        yield '.'.join(extraction)
    yield '.'.join(extraction[1:])


def clean_domain(unclean_domain):
    """Removing errant characters and stuff from a domain name.

    Args:
        unclean_domain: string
    Returns:
        string domain name
    Raises:
        BadDomainError - when a clean domain can't be made
    """
    unclean_domain = unclean_domain.encode('utf-8', errors='ignore').strip().strip('\\')
    extracted = tldextract.extract(unclean_domain)
    if bool(extracted.domain and extracted.suffix):
        start_index = 1 if not extracted.subdomain else 0
        domain = '.'.join(extracted[start_index:]).lstrip('.')
        return domain
    raise BadDomainError('Can not clean {0} {1}'.format(unclean_domain, repr(extracted)))
