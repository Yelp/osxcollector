# -*- coding: utf-8 -*-
import os.path
import re

import simplejson
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.output_filter import OutputFilter


class RelatedToFilesFilter(OutputFilter):

    FILE_NAME_KEYS = [
        'file_path',
        'osxcollector_plist_path'
    ]

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

    def __init__(self, when, initial_terms=None):
        super(RelatedToFilesFilter, self).__init__()
        self._all_blobs = list()
        self._terms = set()
        self._usernames = set()

        self._when = when

        if initial_terms:
            for val in initial_terms:
                self._create_terms(val)

    def _create_terms(self, val):
        for term in os.path.normpath(val.lower()).split(os.path.sep):
            if len(term) > 1 and term not in self.STOP_WORDS:
                self._terms.add(term)

    def filter_line(self, blob):
        self._all_blobs.append(blob)

        if self._when(blob):
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
                if re.search(term, line):
                    blob.setdefault('osxcollector_related', [])
                    blob['osxcollector_related'].append('files')
                    break

        return self._all_blobs
