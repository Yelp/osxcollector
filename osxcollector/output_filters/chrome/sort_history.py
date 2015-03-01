#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# SortHistoryFilter creates a clean sorted Chrome browser history and tags lines with {'osxcollector_browser_history': 'chrome'}
#
from osxcollector.output_filters.base_filters.output_filter import OutputFilter
from osxcollector.output_filters.base_filters.output_filter import run_filter_main


class SortHistoryFilter(OutputFilter):

    """Joins Chrome browser history 'visits' and 'urls' tables, producing a time sorted browser history.

    In the output look for lines where:
    ('osxcollector_section' == 'chrome' and 'osxcollector_subsection' == 'history' and 'osxcollector_table_name' == 'visits')
    for some snazzy browser history stuff.
    """

    def __init__(self, **kwargs):
        super(SortHistoryFilter, self).__init__(**kwargs)

        self._visits_table = dict()
        self._urls_table = dict()

    def filter_line(self, blob):
        """Cache the 'visits' and 'urls' tables."""
        if 'chrome' == blob.get('osxcollector_section') and 'history' == blob.get('osxcollector_subsection'):
            table = blob.get('osxcollector_table_name')

            if 'visits' == table:
                if self._validate_visit(blob):
                    self._visits_table[blob['id']] = blob
                    blob = None  # Consume the line
            elif 'urls' == table:
                if self._validate_urls(blob):
                    self._urls_table[blob['id']] = blob
                    blob = None  # Consume the line

        return blob

    def end_of_lines(self):
        """Join the 'visits' and 'urls' tables into a single browser history and timeline."""
        history = list()

        for visit in self._visits_table.itervalues():
            url = self._urls_table.get(visit.get('url'))
            if url:
                record = {
                    'url': url['url'].encode('utf-8'),
                    'title': url['title'].encode('utf-8'),
                    'last_visit_time': url['last_visit_time'],
                    'visit_time': visit['visit_time'],
                    'core_transition': self.PAGE_TRANSITION.get_core_transition(visit['transition']),
                    'page_transition': self.PAGE_TRANSITION.get_qualifier_transitions(visit['transition']),
                    'osxcollector_browser_history': 'chrome'
                }

                # Add all the OSXCollector specific keys to the record
                for key in visit.keys():
                    if key.startswith('osxcollector_'):
                        record[key] = visit[key]
                for key in url.keys():
                    if key.startswith('osxcollector_') and key not in record:
                        record[key] = url[key]

                history.append(record)

        return sorted(history, key=lambda x: x['last_visit_time'], reverse=True)

    @classmethod
    def _validate_visit(cls, blob):
        """Does the visit dict have the required fields?

        Args:
            blob: a visit dict
        Returns:
            boolean
        """
        required_fields = ['id', 'url', 'visit_time', 'transition']
        return all([field in blob for field in required_fields])

    @classmethod
    def _validate_urls(cls, blob):
        """Does the url dict have the required fields?

        Args:
            blob: a url dict
        Returns:
            boolean
        """
        required_fields = ['id', 'url', 'title', 'last_visit_time']
        return all([field in blob for field in required_fields])

    class PAGE_TRANSITION:

        """Constants that detail page transitions in the Chrome 'visits' table.

        These constants comes from:
        <http://src.chromium.org/svn/trunk/src/content/public/common/page_transition_types_list.h>_
        """
        # User got to this page by clicking a link on another page.
        CORE_LINK = 0

        # User got this page by typing the URL in the URL bar.  This should not be
        # used for cases where the user selected a choice that didn't look at all
        # like a URL; see GENERATED below.
        #
        # We also use this for other "explicit" navigation actions.
        CORE_TYPED = 1

        # User got to this page through a suggestion in the UI, for example,
        # through the destinations page.
        CORE_AUTO_BOOKMARK = 2

        # This is a subframe navigation. This is any content that is automatically
        # loaded in a non-toplevel frame. For example, if a page consists of
        # several frames containing ads, those ad URLs will have this transition
        # type. The user may not even realize the content in these pages is a
        # separate frame, so may not care about the URL (see MANUAL below).
        CORE_AUTO_SUBFRAME = 3

        # For subframe navigations that are explicitly requested by the user and
        # generate new navigation entries in the back/forward list. These are
        # probably more important than frames that were automatically loaded in
        # the background because the user probably cares about the fact that this
        # link was loaded.
        CORE_MANUAL_SUBFRAME = 4

        # User got to this page by typing in the URL bar and selecting an entry
        # that did not look like a URL.  For example, a match might have the URL
        # of a Google search result page, but appear like "Search Google for ...".
        # These are not quite the same as TYPED navigations because the user
        # didn't type or see the destination URL.
        # See also KEYWORD.
        CORE_GENERATED = 5

        # The page was specified in the command line or is the start page.
        CORE_START_PAGE = 6

        # The user filled out values in a form and submitted it. NOTE that in
        # some situations submitting a form does not result in this transition
        # type. This can happen if the form uses script to submit the contents.
        CORE_FORM_SUBMIT = 7

        # The user "reloaded" the page, either by hitting the reload button or by
        # hitting enter in the address bar.  NOTE: This is distinct from the
        # concept of whether a particular load uses "reload semantics" (i.e.
        # bypasses cached data).  For this reason, lots of code needs to pass
        # around the concept of whether a load should be treated as a "reload"
        # separately from their tracking of this transition type, which is mainly
        # used for proper scoring for consumers who care about how frequently a
        # user typed/visited a particular URL.
        #
        # SessionRestore and undo tab close use this transition type too.
        CORE_RELOAD = 8

        # The url was generated from a replaceable keyword other than the default
        # search provider. If the user types a keyword (which also applies to
        # tab-to-search) in the omnibox this qualifier is applied to the transition
        # type of the generated url. TemplateURLModel then may generate an
        # additional visit with a transition type of KEYWORD_GENERATED against the
        # url 'http:#' + keyword. For example, if you do a tab-to-search against
        # wikipedia the generated url has a transition qualifer of KEYWORD, and
        # TemplateURLModel generates a visit for 'wikipedia.org' with a transition
        # type of KEYWORD_GENERATED.
        CORE_KEYWORD = 9

        # Corresponds to a visit generated for a keyword. See description of
        # KEYWORD for more details.
        CORE_KEYWORD_GENERATED = 10

        CORE_MASK = 0xFF

        @classmethod
        def get_core_transition(cls, value):
            """Translates a numeric page transition into a human readable description.

            Args:
                value: A numeric value represented as a Number or String

            Returns:
                A string
            """
            try:
                value = int(value) & cls.CORE_MASK
            except ValueError:
                return 'ERROR'

            if cls.CORE_LINK == value:
                return 'link'
            elif cls.CORE_TYPED == value:
                return 'typed'
            elif cls.CORE_AUTO_BOOKMARK == value:
                return 'auto_bookmark'
            elif cls.CORE_AUTO_SUBFRAME == value:
                return 'auto_subframe'
            elif cls.CORE_MANUAL_SUBFRAME == value:
                return 'manual_subframe'
            elif cls.CORE_GENERATED == value:
                return 'generated'
            elif cls.CORE_START_PAGE == value:
                return 'start_page'
            elif cls.CORE_FORM_SUBMIT == value:
                return 'form_submit'
            elif cls.CORE_RELOAD == value:
                return 'reload'
            elif cls.CORE_KEYWORD == value:
                return 'keyword'
            elif cls.CORE_KEYWORD_GENERATED == value:
                return 'generated'
            return 'UNKNOWN'

        # A managed user attempted to visit a URL but was blocked.
        QUALIFIER_BLOCKED = 0x00800000

        # User used the Forward or Back button to navigate among browsing history.
        QUALIFIER_FORWARD_BACK = 0x01000000

        # User used the address bar to trigger this navigation.
        QUALIFIER_FROM_ADDRESS_BAR = 0x02000000

        # User is navigating to the home page.
        QUALIFIER_HOME_PAGE = 0x04000000

        # The beginning of a navigation chain.
        QUALIFIER_CHAIN_START = 0x10000000

        # The last transition in a redirect chain.
        QUALIFIER_CHAIN_END = 0x20000000

        # Redirects caused by JavaScript or a meta refresh tag on the page.
        QUALIFIER_CLIENT_REDIRECT = 0x40000000

        # Redirects sent from the server by HTTP headers. It might be nice to
        # break this out into 2 types in the future, permanent or temporary, if we
        # can get that information from WebKit.
        QUALIFIER_SERVER_REDIRECT = 0x80000000

        QUALIFIER_MASK = 0xFFFFFF00

        @classmethod
        def get_qualifier_transitions(cls, value):
            qualifiers = []

            try:
                value = int(value) & cls.QUALIFIER_MASK
            except ValueError:
                return qualifiers

            if cls.QUALIFIER_BLOCKED & value:
                qualifiers.append('blocked')

            if cls.QUALIFIER_FORWARD_BACK & value:
                qualifiers.append('forward_back')

            if cls.QUALIFIER_FROM_ADDRESS_BAR & value:
                qualifiers.append('from_address_bar')

            if cls.QUALIFIER_HOME_PAGE & value:
                qualifiers.append('home_page')

            if cls.QUALIFIER_CHAIN_START & value:
                qualifiers.append('chain_start')

            if cls.QUALIFIER_CHAIN_END & value:
                qualifiers.append('chain_end')

            if cls.QUALIFIER_CLIENT_REDIRECT & value:
                qualifiers.append('client_redirect')

            if cls.QUALIFIER_SERVER_REDIRECT & value:
                qualifiers.append('server_redirect')

            return qualifiers


def main():
    run_filter_main(SortHistoryFilter)


if __name__ == "__main__":
    main()
