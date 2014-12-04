# -*- coding: utf-8 -*-
import re
import simplejson
import sys

from osxcollector.osxcollector import DictUtils

from osxcollector.output_filters.output_filter import OutputFilter


class ChainFilter(OutputFilter):

    def __init__(self, chain):
        super(ChainFilter, self).__init__()

        prev_link = None
        for cur_link in chain:
            if prev_link:
                prev_link._next_link = cur_link
            cur_link._next_link = None
            prev_link = cur_link

        self._head_of_chain = chain[0]


    def filter_line(self, blob):
        """Find blacklisted values in a line."""
        return self._on_filter_line(blob, self._head_of_chain)

    def _on_filter_line(self, blob, link):
        if not link or not blob:
            return blob
        return self._on_filter_line(link.filter_line(blob), link._next_link)

    def end_of_lines(self):
        return self._on_end_of_lines(self._head_of_chain)

    def _on_end_of_lines(self, link):
        if not link._next_link:
            return link.end_of_lines()

        filtered_lines = []
        for blob in link.end_of_lines():
            filtered_line = self._on_filter_line(blob, link._next_link)
            if filtered_line:
                filtered_lines.append(filtered_line)

        final_lines = self._on_end_of_lines(link._next_link)
        if final_lines:
            filtered_lines.extend(final_lines)

        return filtered_lines
