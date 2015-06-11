# -*- coding: utf-8 -*-
import time
from datetime import datetime

import testify as T

from osxcollector import osxcollector


def _convert_to_utc(func):
    '''Local time to UTC conversion
    source: http://feihonghsu.blogspot.com/2008/02/converting-from-local-time-to-utc.html
    '''
    def wrapper(dt):
        dt_utc = datetime.utcfromtimestamp(time.mktime(dt.timetuple()))
        return func(dt_utc)

    return wrapper


@_convert_to_utc
def _datetime_to_seconds_since_2001(dt):
    return (dt - osxcollector.DATETIME_2001).total_seconds()


@_convert_to_utc
def _datetime_to_seconds_since_epoch(dt):
    return (dt - osxcollector.DATETIME_1970).total_seconds()


@_convert_to_utc
def _datetime_to_microseconds_since_epoch(dt):
    return (dt - osxcollector.DATETIME_1970).total_seconds() * 1e6


@_convert_to_utc
def _datetime_to_microseconds_since_1601(dt):
    return (dt - osxcollector.DATETIME_1601).total_seconds() * 1e6


DT_BEFORE_MIN = datetime(2002, 7, 8, 14, 28, 22)
"""Date before minimum date"""
DT_VALID = datetime(2014, 7, 8, 14, 28, 22)
"""Valid date that should not cause problems after convertion"""
DT_FUTURE = datetime(datetime.now().year + 1, 7, 8, 14, 28, 22)
"""Date in the future"""

DT_VALID_AS_STRING = '2014-07-08 14:28:22'
"""String representation of DT_VALID"""


class SecondsSince2001ToDatetimeTestCase(T.TestCase):

    def test_seconds_since_2001_to_datetime(self):
        sec_since_2001 = _datetime_to_seconds_since_2001(DT_VALID)
        dt = osxcollector._seconds_since_2001_to_datetime(sec_since_2001)
        T.assert_equal(dt, DT_VALID)

    def test_datetime_before_min_year(self):
        sec_since_2001 = _datetime_to_seconds_since_2001(DT_BEFORE_MIN)
        dt = osxcollector._seconds_since_2001_to_datetime(sec_since_2001)
        T.assert_equal(dt, None)

    def test_datetime_in_future(self):
        sec_since_2001 = _datetime_to_seconds_since_2001(DT_FUTURE)
        dt = osxcollector._seconds_since_2001_to_datetime(sec_since_2001)
        T.assert_equal(dt, None)


class SecondsSinceEpochToDatetimeTestCase(T.TestCase):

    def test_seconds_since_epoch_to_datetime(self):
        sec_since_epoch = _datetime_to_seconds_since_epoch(DT_VALID)
        dt = osxcollector._seconds_since_epoch_to_datetime(sec_since_epoch)
        T.assert_equal(dt, DT_VALID)

    def test_datetime_before_min_year(self):
        sec_since_epoch = _datetime_to_seconds_since_epoch(DT_BEFORE_MIN)
        dt = osxcollector._seconds_since_epoch_to_datetime(sec_since_epoch)
        T.assert_equal(dt, None)

    def test_datetime_in_future(self):
        sec_since_epoch = _datetime_to_seconds_since_epoch(DT_FUTURE)
        dt = osxcollector._seconds_since_epoch_to_datetime(sec_since_epoch)
        T.assert_equal(dt, None)


class MicrosecondsSinceEpochToDatetimeTestCase(T.TestCase):

    def test_microseconds_since_epoch_to_datetime(self):
        microsec_since_epoch = _datetime_to_microseconds_since_epoch(DT_VALID)
        dt = osxcollector._microseconds_since_epoch_to_datetime(microsec_since_epoch)
        T.assert_equal(dt, DT_VALID)

    def test_datetime_before_min_year(self):
        microsec_since_epoch = _datetime_to_microseconds_since_epoch(DT_BEFORE_MIN)
        dt = osxcollector._microseconds_since_epoch_to_datetime(microsec_since_epoch)
        T.assert_equal(dt, None)

    def test_datetime_in_future(self):
        microsec_since_epoch = _datetime_to_microseconds_since_epoch(DT_FUTURE)
        dt = osxcollector._microseconds_since_epoch_to_datetime(microsec_since_epoch)
        T.assert_equal(dt, None)


class MicrosecondsSince1601ToDatetimeTestCase(T.TestCase):

    def test_microseconds_since_1601_to_datetime(self):
        ms_since_1601 = _datetime_to_microseconds_since_1601(DT_VALID)
        dt = osxcollector._microseconds_since_1601_to_datetime(ms_since_1601)
        T.assert_equal(dt, DT_VALID)

    def test_datetime_before_min_year(self):
        ms_since_1601 = _datetime_to_microseconds_since_1601(DT_BEFORE_MIN)
        dt = osxcollector._microseconds_since_1601_to_datetime(ms_since_1601)
        T.assert_equal(dt, None)

    def test_datetime_in_future(self):
        ms_since_1601 = _datetime_to_microseconds_since_1601(DT_FUTURE)
        dt = osxcollector._microseconds_since_1601_to_datetime(ms_since_1601)
        T.assert_equal(dt, None)


class ValueToDatetimeTestCase(T.TestCase):

    """Tests whether the _value_to_datetime function works correctly for all of the different
    date formats. That way we should know that the heuristic regarding the order
    of the convertion calls for the specific date format inside this function works fine.
    """

    def test_seconds_since_2001_to_datetime(self):
        sec_since_2001 = _datetime_to_seconds_since_2001(DT_VALID)
        dt = osxcollector._value_to_datetime(sec_since_2001)
        T.assert_equal(dt, DT_VALID)

    def test_seconds_since_epoch_to_datetime(self):
        sec_since_epoch = _datetime_to_seconds_since_epoch(DT_VALID)
        dt = osxcollector._value_to_datetime(sec_since_epoch)
        T.assert_equal(dt, DT_VALID)

    def test_microseconds_since_epoch_to_datetime(self):
        microsec_since_epoch = _datetime_to_microseconds_since_epoch(DT_VALID)
        dt = osxcollector._value_to_datetime(microsec_since_epoch)
        T.assert_equal(dt, DT_VALID)

    def test_microseconds_since_1601_to_datetime(self):
        microsec_since_1601 = _datetime_to_microseconds_since_1601(DT_VALID)
        dt = osxcollector._value_to_datetime(microsec_since_1601)
        T.assert_equal(dt, DT_VALID)


class NormalizeValueTestCase(T.TestCase):

    """Tests _normalize_val function."""

    def test_normalize_basestring(self):
        s = "basestring here"
        val = osxcollector._normalize_val(s)
        T.assert_equal(s, val)

    def test_normalize_unicode(self):
        u = '\u20AC'
        val = osxcollector._normalize_val(u)
        T.assert_truthy(isinstance(val, unicode))

    def test_normalize_unicode_error(self):
        s = 'Was\x9f'
        val = osxcollector._normalize_val(s)
        T.assert_falsey(isinstance(val, unicode))

    def test_normalize_buffer_to_unicode(self):
        b = buffer("this is buffer")
        val = osxcollector._normalize_val(b)
        T.assert_truthy(isinstance(val, unicode))

    def test_normalize_datetime(self):
        """Tests whether timestamps are resolved to datetime string representation,
        based on passed key value."""

        keys_that_hint_about_being_a_date = ["start date:", "TIME FINISHED", "in UTC", "event date"]
        for key in keys_that_hint_about_being_a_date:
            sec_since_2001 = _datetime_to_seconds_since_2001(DT_VALID)
            val = osxcollector._normalize_val(sec_since_2001, key)
            T.assert_equal(DT_VALID_AS_STRING, val)

        # key contains 'date' however the value is not date
        not_a_date = "yes, it includes"
        val = osxcollector._normalize_val(not_a_date, "includes_dates")
        T.assert_equal(not_a_date, val)
