#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# FindExtensionsFilter reads the Chrome preferences JSON blob and creates records about the extensions and plugins.
#
from osxcollector.osxcollector import DictUtils
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main


class FindExtensionsFilter(OutputFilter):

    """Reads the Chrome preferences JSON blob and creates records about the extensions and plugins.

    In the output look a line where:
    ('osxcollector_section' == 'chrome' and 'osxcollector_subsection' == 'preferences')
    and then parse the heck out of the extensions.
    """

    def __init__(self, **kwargs):
        super(FindExtensionsFilter, self).__init__(**kwargs)
        self._new_lines = []

    def filter_line(self, blob):
        if 'chrome' != blob.get('osxcollector_section') or 'preferences' != blob.get('osxcollector_subsection'):
            return blob

        extensions_blob = DictUtils.get_deep(blob, 'contents.extensions.settings', {})
        for key in extensions_blob.keys():
            setting = extensions_blob[key]
            extension = {
                'osxcollector_section': 'chrome',
                'osxcollector_subsection': 'extensions',
                'osxcollector_incident_id': 'osxcollector_incident_id',
                'state': setting.get('state'),
                'was_installed_by_default': setting.get('was_installed_by_default'),
                'name': DictUtils.get_deep(setting, 'manifest.name'),
                'description': DictUtils.get_deep(setting, 'manifest.description'),
                'path': setting.get('path')
            }
            if blob.get('osxcollector_username'):
                extension['osxcollector_username'] = blob['osxcollector_username']

            self._new_lines.append(extension)

        return None

    def end_of_lines(self):
        return self._new_lines


def main():
    run_filter_main(FindExtensionsFilter)


if __name__ == "__main__":
    main()
