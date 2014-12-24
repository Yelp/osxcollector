# -*- coding: utf-8 -*-
#
# ThreatFeedFilter is a base class to find suspicious IOC using some random API.
# RateLimiter calls for easy rate limiting of HTTP requests
#
import sys
import time
from collections import namedtuple
from traceback import extract_tb

import grequests
from osxcollector.output_filters.base_filters.output_filter import OutputFilter


class RateLimiter(object):

    """Limits how many calls can be made per second"""

    CallRecord = namedtuple('CallRecord', ['time', 'num_calls'])

    def __init__(self, calls_per_sec):
        self._max_calls_per_second = calls_per_sec
        self._call_times = []
        self._outstanding_calls = 0

    def make_calls(self, num_calls=1):
        """Adds appropriate sleep to avoid making too many calls.

        Args:
            num_calls: int the number of calls which will be made
        """
        self._cull()
        while self._outstanding_calls + num_calls > self._max_calls_per_second:
            time.sleep(0.5)
            self._cull()

        self._call_times.append(self.CallRecord(time=time.time(), num_calls=num_calls))
        self._outstanding_calls += num_calls

    def _cull(self):
        """Remove calls more than 1 minutes old from the queue."""
        right_now = time.time()

        cull_from = -1
        for index in xrange(len(self._call_times)):
            if right_now - self._call_times[index].time >= 1.0:
                cull_from = index
                self._outstanding_calls -= self._call_times[index].num_calls
            else:
                break

        if cull_from > -1:
            self._call_times = self._call_times[cull_from + 1:]


class MultiRequest(object):

    def __init__(self, default_headers=None, max_requests=20, rate_limit=0, req_timeout=25.0):
        self._default_headers = default_headers
        self._max_requests = max_requests
        self._req_timeout = req_timeout
        self._rate_limiter = RateLimiter(rate_limit) if rate_limit else None

    def post(self, url, data=None, to_json=True):
        sys.stderr.write(repr(self._default_headers))

        request = grequests.post(url, headers=self._default_headers, data=data, timeout=self._req_timeout)
        response = grequests.map([request])
        if to_json:
            sys.stderr.write(response[0].url)
            sys.stderr.write('\n')

            return response[0].json()
        return response[0]

    def multi_get_urls(self, urls, to_json=True):
        params = [None] * len(urls)
        return self.multi_get(urls, params, to_json)

    def multi_get_params(self, url, params, to_json=True):
        urls = [url] * len(params)
        return self.multi_get(urls, params, to_json)

    def multi_get(self, urls, params, to_json=True):
        assert isinstance(urls, list)
        assert isinstance(params, list)
        assert len(urls) == len(params)

        all_responses = []

        zipped = zip(urls, params)
        chunks = [zipped[pos:pos + self._max_requests] for pos in xrange(0, len(zipped), self._max_requests)]

        for chunk in chunks:
            if self._rate_limiter:
                self._rate_limiter.make_calls(num_calls=len(chunk))

            requests = [grequests.get(url, headers=self._default_headers, params=param, timeout=self._req_timeout) for url, param in chunk]
            for response in grequests.map(requests):
                if 200 == response.status_code:
                    if to_json:
                        sys.stderr.write(response.url)
                        sys.stderr.write('\n')
                        all_responses.append(response.json())
                    else:
                        all_responses.append(response)
                else:
                    sys.stderr.write('REQUESTS FAILED {0}\n'.format(response.status_code))
                    all_responses.append(None)

        return all_responses

    @classmethod
    def error_handling(cls, fn):
        """Decorator to handle errors while calling out to grequests."""
        def wrapper(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
                return result
            except Exception as e:
                # de_args = repr([a for a in args]) or ''
                # de_kwargs = repr([(a, kwargs[a]) for a in kwargs]) or ''
                # sys.stderr.write('[ERROR] calling {0} {1} {2}\n'.format(fn.__name__, de_args, de_kwargs))

                exc_type, _, exc_traceback = sys.exc_info()
                sys.stderr.write('[ERROR] {0} {1}\n'.format(exc_type, extract_tb(exc_traceback)))

                if hasattr(e, 'response'):
                    sys.stderr.write('[ERROR] request {0}\n'.format(repr(e.response)))
                if hasattr(e, 'request'):
                    sys.stderr.write('[ERROR] request {0}\n'.format(repr(e.request)))

                raise e
        return wrapper


class ThreatFeedFilter(OutputFilter):

    """A base class to find info on IOCs using some random API.

    Derrived classes need only to implement _lookup_iocs()

    It is assumed that the API uses an api_key stored in the config.
    """

    def __init__(self, ioc_key, output_key, lookup_when=None, suspicious_when=None, api_key=None):
        """Read API config

        Args:
            ioc_key: key for finding IOCs in the input
            output_key: key to use to add threat info to the output
            lookup_when: a boolean function to call to decide whether to try a lookup for a blob
            is_suspicious_when: a boolean function to call to decide whether a blob is already known to be suspicious
            api_key: name of the key in the 'api_key' section of config
        """
        super(ThreatFeedFilter, self).__init__()

        if api_key:
            self._api_key = self.config.get_config('api_key.{0}'.format(api_key))

        self._lookup_when = lookup_when
        self._is_suspicious_when = suspicious_when
        self._blobs_with_iocs = list()
        self._all_iocs = set()
        self._suspicious_iocs = set()
        self._threat_info_by_iocs = dict()

        self._ioc_key = ioc_key
        self._output_key = output_key

    def _lookup_iocs(self):
        """Caches the threat info for a set of IOCs into self._threat_info_by_iocs

        This is the only method a derived class needs to implement.
        The set of IOCs to lookup is self._all_iocs
        Anything to be added to the output should be stored in the dict self._threat_info_by_iocs which is keyed by IOC
        """
        raise NotImplementedError('Derived classes must implement _lookup_iocs')

    def filter_line(self, blob):
        """Accumulate IOCs to lookup with the ThreatFeed.

        Args:
            blob: A dict

        Returns:
            A Line or None
        """
        if self._ioc_key in blob and (not self._lookup_when or self._lookup_when(blob)):
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            if len(ioc_list) > 10:
                return blob

            is_suspicious = self._is_suspicious_when and self._is_suspicious_when(blob)
            for ioc in ioc_list:
                if not len(ioc):
                    continue

                self._all_iocs.add(ioc)
                if is_suspicious:
                    self._suspicious_iocs.add(ioc)

            self._blobs_with_iocs.append(blob)
            return None
        else:
            return blob

    def end_of_lines(self):
        """Performs threat feed lookup on the IOCs and adds output to the stored Lines.

        Returns:
            An array of strings
        """
        self._lookup_iocs()
        self._add_threat_info_to_blobs()
        return self._blobs_with_iocs

    def _add_threat_info_to_blobs(self):
        """Adds threat info to blobs"""
        for blob in self._blobs_with_iocs:
            ioc_list = blob[self._ioc_key]
            if isinstance(ioc_list, basestring):
                ioc_list = [ioc_list]

            for ioc in ioc_list:
                threat_info = self._threat_info_by_iocs.get(ioc)
                if threat_info:
                    blob.setdefault(self._output_key, [])
                    blob[self._output_key].append(threat_info)
