#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# RelatedFilesFilter finds files related to specific terms or file names.
#
import os.path
from argparse import ArgumentParser

import simplejson

from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main


class RelatedFilesFilter(OutputFilter):

    """RelatedFilesFilter finds files related to specific terms or file names.

    The file paths passed to the filter during creation are split into arrays of
    directory or file names. Anything matching a stop list of common directory names
    is discarded.
    """

    def __init__(self, when=None, file_terms=None, **kwargs):
        super(RelatedFilesFilter, self).__init__()
        self._all_blobs = list()
        self._terms = set()
        self._usernames = set()

        self._when = when

        if file_terms:
            for val in file_terms:
                self._create_terms(val)

    def _create_terms(self, val):
        for term in os.path.normpath(val.lower()).split(os.path.sep):
            if len(term) > 1 and term not in self.STOP_WORDS:
                self._terms.add(term)

    def filter_line(self, blob):
        self._all_blobs.append(blob)

        if self._when and self._when(blob):
            for key in self.FILE_NAME_KEYS:
                val = DictUtils.get_deep(blob, key)
                if val:
                    self._create_terms(val)
        if 'osxcollector_username' in blob:
            self._usernames.add(blob['osxcollector_username'].lower())

        return None

    def end_of_lines(self):
        self._terms = self._terms - self._usernames

        for blob in self._all_blobs:
            line = simplejson.dumps(blob).lower()
            for term in self._terms:
                if term in line:
                    blob.setdefault('osxcollector_related', {})
                    blob['osxcollector_related'].setdefault('files', [])
                    blob['osxcollector_related']['files'].append(term)

        return self._all_blobs

    def get_commandline_args(self):
        parser = ArgumentParser()
        group = parser.add_argument_group('RelatedFilesFilter')
        group.add_argument('-f', '--file-term', dest='file_terms', default=[], action='append',
                           help='[OPTIONAL] Suspicious terms to use in pivoting through file names.  May be specified more than once.')
        return parser

    @property
    def terms(self):
        return self._terms

    @property
    def usernames(self):
        return self._usernames

    # Keys to look in to find file paths
    FILE_NAME_KEYS = [
        'file_path',
        'osxcollector_plist_path'
    ]

    # Words that can never be terms
    STOP_WORDS = [
        'applications',
        'bin',
        'contents',
        'cores',
        'coreservices',
        'dev',
        'downloads',
        'extensions',
        'frameworks',
        'helpers',
        'home',
        'information',
        'libexec',
        'libraries',
        'library',
        'macos',
        'malware',
        'net',
        'network',
        'opt',
        'plugins',
        'private',
        'privateframeworks',
        'python',
        'resources',
        'sbin',
        'support',
        'system',
        'tmp',
        'user',
        'users',
        'usr',
        'utilities',
        'versions',
        'var'
    ]


def main():
    run_filter_main(RelatedFilesFilter)


if __name__ == "__main__":
    main()
