#!/usr/bin/python
# -*- coding: utf-8 -*-
import copy
import simplejson

from osxcollector.output_filters.output_filter import OutputFilter
from osxcollector.output_filters.output_filter import run_filter


class FirefoxHistoryFilter(OutputFilter):

    """Joins Firefox browser history 'visits' and 'urls' tables, producing a time sorted browser history.

    In the output look for lines where:
    ('osxcollector_section' == 'chrome' and 'osxcollector_subsection' == 'history' and 'osxcollector_table_name' == 'visits')
    for some snazzy browser history stuff.
    """

    def __init__(self):
        super(FirefoxHistoryFilter, self).__init__()

        self._visits_table = dict()
        self._places_table = dict()

    def filter_line(self, line):
        """Cache the 'visits' and 'urls' tables."""
        try:
            blob = simplejson.loads(line)
        except:
            return line

        if 'firefox' == blob.get('osxcollector_section') and 'history' == blob.get('osxcollector_subsection'):
            table = blob.get('osxcollector_table_name')

            if 'moz_historyvisits' == table:
                if self._validate_visit(blob):
                    self._visits_table[blob['place_id']] = blob
                    line = None  # Consume the line
            elif 'moz_places' == table:
                if self._validate_places(blob):
                    self._places_table[blob['id']] = blob
                    line = None  # Consume the line

        return line

    def end_of_lines(self):
        """Join the 'visits' and 'urls' tables into a single browser history and timeline."""
        history = list()

        for visit in self._visits_table.itervalues():
            place = self._places_table.get(visit.get('place_id'))
            if place:
                add_keys = [key for key in visit.keys() if key not in place.keys()]
                record = copy.deepcopy(place)
                for key in add_keys:
                    record[key] = visit[key]

                history.append(record)

        return ['{0}\n'.format(simplejson.dumps(blob)) for blob in sorted(history, key=lambda x: x['last_visit_date'], reverse=True)]

    @classmethod
    def _validate_visit(cls, blob):
        """Does the visit dict have the required fields?

        Args:
            blob: a visit dict
        Returns:
            boolean
        """
        required_fields = ['place_id']
        return all([field in blob for field in required_fields])

    @classmethod
    def _validate_places(cls, blob):
        """Does the place dict have the required fields?

        Args:
            blob: a place dict
        Returns:
            boolean
        """
        required_fields = ['id']
        return all([field in blob for field in required_fields])


def main():
    run_filter(FirefoxHistoryFilter())


if __name__ == "__main__":
    main()
