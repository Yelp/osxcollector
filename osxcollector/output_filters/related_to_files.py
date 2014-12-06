# -*- coding: utf-8 -*-
import simplejson
import os.path
import re

from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.output_filter import OutputFilter


class RelatedToFiles(OutputFilter):

    FILE_NAME_KEYS = [
        'file_path',
        'osxcollector_plist_path'
    ]

    STOP_WORDS = [
        'contents',  # 925
        'malware',  # 898
        'macos',  # 624
        'library',  # 565
        'system',  # 546
        'extensions',  # 374
        'users',  # 335
        'downloads',  # 334
        'plugins',  # 228
        'applications',  # 193
        'usr',  # 127
        'resources',  # 93
        'frameworks',  # 82
        'libexec',  # 75
        'coreservices',  # 72
        'versions',  # 53
        'sbin',  # 47
        'utilities',  # 44
        'privateframeworks',  # 41
        'support',  # 26
        'libraries',  # 11
        'helpers',  # 11
        'bin'  # 10
    ]

    def __init__(self, when, initial_terms=None):
        super(RelatedToFiles, self).__init__()
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
        look_for = list(self._terms - self._usernames)

        for blob in self._all_blobs:
            line = simplejson.dumps(blob).lower()
            for term in look_for:
                if re.search(term, line):
                    blob.setdefault('osxcollector_related', [])
                    blob['osxcollector_related'].append('files')
                    break

        return self._all_blobs
