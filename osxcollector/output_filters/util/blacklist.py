# -*- coding: utf-8 -*-
#
# Utilities for dealing with blacklists
#
import re

from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.exceptions import MissingConfigError
from osxcollector.output_filters.util.domains import clean_domain


def create_blacklist(config_chunk):
    """Reads the config and builds a Blacklist.

    The blacklist config is sufficiently complex that much of this method deals with simply validating config

    Args:
        config_chunk: A dict of config for building the blacklist
    Returns:
        A Blacklist
    Raises:
        MissingConfigError - when required key does not exist.
    """
    required_keys = ['blacklist_name', 'blacklist_keys', 'blacklist_file_path']
    if not all([key in config_chunk.keys() for key in required_keys]):
        raise MissingConfigError('Blacklist config is missing a required key.\nRequired keys are: {0}'.format(repr(required_keys)))

    if not isinstance(config_chunk['blacklist_keys'], list):
        raise MissingConfigError('The value of \'blacklist_keys\' in Blacklist config must be a list')

    blacklist_name = config_chunk.get('blacklist_name')
    blacklist_keys = config_chunk.get('blacklist_keys')
    blacklist_file_path = config_chunk.get('blacklist_file_path')
    blacklist_is_regex = config_chunk.get('blacklist_is_regex', False)
    blacklist_is_domains = config_chunk.get('blacklist_is_domains', False)
    return Blacklist(blacklist_name, blacklist_keys, blacklist_file_path, blacklist_is_regex, blacklist_is_domains)


class Blacklist(object):

    def __init__(self, name, blacklisted_keys, file_path, is_regex=False, is_domains=False):
        """Build a blacklist from the data in the blacklist file.

        Built in smarts make it easy to build a blacklist of domains

        Raises:
            MissingConfigError - when required config key does not exist.
        """
        self._name = name
        self._file_path = file_path
        self._blacklisted_keys = blacklisted_keys
        self._is_domains = is_domains
        self._is_regex = is_regex or self._is_domains
        self._blacklisted_values = []

        for line in self._read_blacklist_file_contents():
            if not line.startswith('#'):
                line = line.strip()
                if line:
                    self._blacklisted_values.append(line)
        if self._is_regex:
            self._blacklisted_values = [self._convert_to_regex(val) for val in self._blacklisted_values]

    def _read_blacklist_file_contents(self):
        try:
            with open(self._file_path, 'r') as value_file:
                return value_file.readlines()
        except IOError as e:
            raise MissingConfigError(e.msg)

    def _convert_to_regex(self, blacklisted_value):
        """Convert a blacklisted_value to a regex.

        Args:
            blacklisted_value - string of value on a blacklist
            blacklist_is_domains - Boolean if true, the blacklisted_value is treated as a domain.
        Returns:
            a compliled regex object
        """
        if self._is_domains:
            domain = clean_domain(blacklisted_value)
            blacklisted_value = '^(.+\.)*{0}$'.format(domain.replace('.', '\.').replace('-', '\-'))
        return re.compile(blacklisted_value)

    def match_line(self, blob):
        """Determines whether a line matches the blacklist."""
        for key in self._blacklisted_keys:
            values = DictUtils.get_deep(blob, key)
            if not values:
                continue

            if self.match_values(values):
                return True

        return False

    def match_values(self, values):
        """Determines whether an array of values match the blacklist."""
        if not isinstance(values, list):
            values = [values]

        for val in values:
            if self._is_regex:
                if any([regex_to_match.search(val) for regex_to_match in self._blacklisted_values]):
                    return True
            else:
                if any([val_to_match == val for val_to_match in self._blacklisted_values]):
                    return True

        return False

    @property
    def name(self):
        return self._name
