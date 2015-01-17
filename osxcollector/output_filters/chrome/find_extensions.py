#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# FindExtensionsFilter reads the Chrome preferences JSON blob and creates records about the extensions and plugins.
#
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter


class FindExtensionsFilter(OutputFilter):

    """Reads the Chrome preferences JSON blob and creates records about the extensions and plugins.

    In the output look a line where:
    ('osxcollector_section' == 'chrome' and 'osxcollector_subsection' == 'preferences')
    and then parse the heck out of the extensions.
    """

    def __init__(self):
        super(FindExtensionsFilter, self).__init__()
        self._new_lines = []

    def filter_line(self, blob):
        if 'chrome' != blob.get('osxcollector_section') and 'preferences' != blob.get('osxcollector_subsection'):
            return blob

        extensions_blob = DictUtils.get_deep(blob, 'contents.extensions.settings', {})
        for key in extensions_blob.keys():
            val = extensions_blob[key]
            val['osxcollector_section'] = 'chrome'
            val['osxcollector_subsection'] = 'extensions'
            val['osxcollector_incident_id'] = blob['osxcollector_incident_id']
            if blob.get('osxcollector_username'):
                val['osxcollector_username'] = blob['osxcollector_username']

            self._new_lines.append(val)

    def end_of_lines(self):
        return self._new_lines


def main():
    run_filter(FindExtensionsFilter())


if __name__ == "__main__":
    main()
