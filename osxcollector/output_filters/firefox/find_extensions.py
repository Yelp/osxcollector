#!/usr/bin/env python

# -*- coding: utf-8 -*-
#
# FindExtensionsFilter reads the Firefox JSON blobs and creates records about the extensions and plugins.
#
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter


class FindExtensionsFilter(OutputFilter):

    """Reads the Firefox JSON blobs and creates records about the extensions and plugins.

    In the output look a line where:
    ('osxcollector_section' == 'firefox' and 'osxcollector_subsection' == 'json_files')
    and then parse the heck out of the extensions.
    """

    def __init__(self):
        super(FindExtensionsFilter, self).__init__()
        self._new_lines = []

    def filter_line(self, blob):
        if 'chrome' != blob.get('osxcollector_section') and 'json_files' != blob.get('osxcollector_subsection'):
            return blob

        if blob.get('osxcollector_json_file') not in ['addons.json', 'extensions.json']:
            return blob

        extensions_blobs = DictUtils.get_deep(blob, 'contents.addons', [])
        for addon in extensions_blobs:
            extension = {
                'osxcollector_section': 'firefox',
                'osxcollector_subsection': 'extensions',
                'osxcollector_incident_id': 'osxcollector_incident_id',
                'name': DictUtils.get_deep(addon, 'defaultLocale.name', addon.get('name')),
                'description': DictUtils.get_deep(addon, 'defaultLocale.description', addon.get('description')),
                'path': addon.get('id')
            }
            if blob.get('osxcollector_username'):
                extension['osxcollector_username'] = blob['osxcollector_username']

            self._new_lines.append(extension)

    def end_of_lines(self):
        return self._new_lines


def main():
    run_filter(FindExtensionsFilter())


if __name__ == "__main__":
    main()
