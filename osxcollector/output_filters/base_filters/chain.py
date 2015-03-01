# -*- coding: utf-8 -*-
#
# ChainFilter is a base class that passes each line through a chain of OutputFilters.
#
from argparse import ArgumentParser

from osxcollector.output_filters.base_filters.output_filter import OutputFilter


class ChainFilter(OutputFilter):

    """ChainFilter is a base class that passes each line through a chain of OutputFilters.

    This is useful for constructing a single OutputFilter that does multiple things without
    having to run `python -m FilterOne | python -m FilterTwo | python -m FilterThree`.
    """

    def __init__(self, chain, **kwargs):
        """Adds the property _next_link to each OutputFilter in the chain.

        Treating the chain as a linked list makes it easy to know which filter runs after the current filter.
        _next_link should be present and have a value of None for the final link in the chain.

        Args:
            chain: An enumerable of OutputFilters.
        """
        super(ChainFilter, self).__init__(**kwargs)

        prev_link = None
        for cur_link in chain:
            if prev_link:
                prev_link._next_link = cur_link
            cur_link._next_link = None
            prev_link = cur_link

        self._head_of_chain = chain[0]

    def filter_line(self, blob):
        """Each Line of OSXCollector output will be passed to filter_line.

        Passes the line to the filter at the head of the chain. Output from each filter flows to it's _next_link.

        Args:
            blob: A dict representing one line of output from OSXCollector.
        Returns:
            A dict or None
        """
        return self._on_filter_line(blob, self._head_of_chain)

    def _on_filter_line(self, blob, link):
        """Pass the line to a link in the chain and pass any output to the next link.

        Args:
            blob: A dict representing one line of output from OSXCollector.
            link: An OutputFilter
        Returns:
            A dict or None
        """
        if not link or not blob:
            return blob
        return self._on_filter_line(link.filter_line(blob), link._next_link)

    def end_of_lines(self):
        """Pass end_of_lines to the filter at the head of the chain.

        Returns:
            An enumerable of dicts
        """
        return self._on_end_of_lines(self._head_of_chain)

    def _on_end_of_lines(self, link):
        """Pass end_of_lines to a link in the chain and pass any output to the next link.

        Args:
            link: An OutputFilter
        Returns:
            An enumerable of dicts
        """
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

    def get_argument_parser(self):
        """Collects the ArgumentParsers from every OutputFilter in the chain.

        Returns:
            An `argparse.ArgumentParser`
        """
        parsers_to_chain = []

        cur_link = self._head_of_chain
        while cur_link:
            arg_parser = cur_link.get_argument_parser()
            if arg_parser:
                parsers_to_chain.append(arg_parser)
            cur_link = cur_link._next_link

        parser = self._on_get_argument_parser()
        if parser:
            parsers_to_chain.append(parser)

        if parsers_to_chain:
            return ArgumentParser(parents=parsers_to_chain, conflict_handler='resolve')

        return None

    def _on_get_argument_parser(self):
        """Returns an ArgumentParser with arguments for just this OutputFilter (not the contained chained OutputFilters).

        Returns:
            An `argparse.ArgumentParser`
        """
        return None
