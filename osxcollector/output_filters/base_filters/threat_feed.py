# -*- coding: utf-8 -*-
#
# ThreatFeedFilter is a base class to find suspicious IOC using some random API.
# RateLimiter calls for easy rate limiting of HTTP requests
#
import sys
import time
from collections import namedtuple
from traceback import extract_tb
from traceback import format_list

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
            time.sleep(0)  # yield
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


class InvalidRequestError(Exception):

    """Raised by MultiRequest when it can't figure out how to make a request."""
    pass


class MultiRequest(object):

    """Wraps grequests to make simultaneous HTTP requests.

    Can use a RateLimiter to limit # of outstanding requests.
    `multi_get` and `multi_post` try to be smart about how many requests to issue:

    * One url & one param - One request will be made.
    * Multiple url & one query param - Multiple requests will be made, with differing urls and the same query param.
    * Multiple url & mulitple query params - Multiple requests will be made, with the same url and differning query params.
    """

    _VERB_GET = 'GET'
    _VERB_POST = 'POST'

    def __init__(self, default_headers=None, max_requests=20, rate_limit=0, req_timeout=25.0):
        """Create the MultiRequest.

        Args:
            default_headers - A dict of headers which will be added to every request
            max_requests - Maximum number of requests to issue at once
            rate_limit - Maximum number of requests to issue per second
            req_timeout - Maximum number of seconds to wait without reading a response byte before deciding an error has occurred
        """
        self._default_headers = default_headers
        self._max_requests = max_requests
        self._req_timeout = req_timeout
        self._rate_limiter = RateLimiter(rate_limit) if rate_limit else None

    def multi_get(self, urls, query_params=None, to_json=True):
        """Issue multiple GET requests.

        Args:
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            a list of dicts if to_json is set of grequest.response otherwise.
        Raises:
            InvalidRequestError - Can not decide how many requests to issue.
        """
        return self._multi_request(MultiRequest._VERB_GET, urls, query_params, None, to_json)

    def multi_post(self, urls, query_params=None, data=None, to_json=True):
        """Issue multiple POST requests.

        Args:
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            data - None, a dict or string, or a list of dicts and strings representing the data body.
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            a list of dicts if to_json is set of grequest.response otherwise.
        Raises:
            InvalidRequestError - Can not decide how many requests to issue.
        """
        return self._multi_request(MultiRequest._VERB_POST, urls, query_params, data, to_json)

    def _create_request(self, verb, url, query_params=None, data=None):
        """Helper method to create a single `grequests.post` or `grequests.get`.

        Args:
            verb - MultiRequest._VERB_POST or MultiRequest._VERB_GET
            url - A string URL
            query_params - None or a dict
            data - None or a string or a dict
        Returns:
            requests.PreparedRequest
        Raises:
            InvalidRequestError - if an invalid verb is passed in.
        """
        if MultiRequest._VERB_POST == verb:
            return grequests.post(url, headers=self._default_headers, params=query_params, data=data, timeout=self._req_timeout)
        elif MultiRequest._VERB_GET == verb:
            return grequests.get(url, headers=self._default_headers, params=query_params, data=data, timeout=self._req_timeout)
        else:
            raise InvalidRequestError('Invalid verb {0}'.format(verb))

    def _zip_request_params(self, urls, query_params, data):
        """Massages inputs and returns a list of 3-tuples zipping them up.

        This is all the smarts behind deciding how many requests to issue.
        It's fine for an input to have 0, 1, or a list of values.
        If there are two inputs each with a list of values, the cardinality of those lists much match.

        Args:
            urls - 1 string URL or a list of URLs
            query_params - None, 1 dict, or a list of dicts
            data - None, 1 dict or string, or a list of dicts or strings
        Returns:
            A list of 3-tuples (url, query_param, data)
        Raises:
            InvalidRequestError - if cardinality of lists does not match
        """

        # Everybody gets to be a list
        if not isinstance(urls, list):
            urls = [urls]
        if not isinstance(query_params, list):
            query_params = [query_params]
        if not isinstance(data, list):
            data = [data]

        # Counts must not mismatch
        url_count = len(urls)
        query_param_count = len(query_params)
        data_count = len(data)

        max_count = max(url_count, query_param_count, data_count)

        if ((url_count < max_count and url_count > 1) or
                (query_param_count < max_count and query_param_count > 1) or
                (data_count < max_count and data_count > 1)):
            raise InvalidRequestError('Mismatched parameter count url_count:{0} query_param_count:{1} data_count:{2} max_count:{3}',
                                      url_count, query_param_count, data_count, max_count)

        # Pad out lists
        if url_count < max_count:
            urls = urls * max_count
        if query_param_count < max_count:
            query_params = query_params * max_count
        if data_count < max_count:
            data = data * max_count

        return zip(urls, query_params, data)

    class _FakeResponse(object):

        """_FakeResponse looks enough like a response from grequests to handle when grequests has no response.

        Attributes:
            request - The request object
            status_code - The HTTP response status code
        """

        def __init__(self, request, status_code):
            self._request = request
            self._status_code = status_code

        @property
        def request(self):
            return self._request

        @property
        def status_code(self):
            return self._status_code

        def json(self):
            """Convert the response body to a dict."""
            return {}

    def _wait_for_response(self, requests, to_json):
        """Issue a batch of requests and wait for the responses.

        Args:
            requests - A list of requests
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            A list of dicts if to_json, a list of grequest.response otherwise
        """
        all_responses = []

        for request, response in zip(requests, grequests.map(requests)):
            if not response:
                response = MultiRequest._FakeResponse(request, '<UNKNOWN>')

            if 200 != response.status_code:
                sys.stderr.write('[ERROR] url[{0}] status_code[{1}]\n'.format(response.request.url, response.status_code))

            if to_json:
                # TODO - Add an option for printing this
                sys.stderr.write(response.request.url)
                sys.stderr.write('\n')
                all_responses.append(response.json())
            else:
                all_responses.append(response)

        return all_responses

    def _multi_request(self, verb, urls, query_params, data, to_json=True):
        """Issues multiple batches of simultaneous HTTP requests and waits for responses.

        Args:
            verb - MultiRequest._VERB_POST or MultiRequest._VERB_GET
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            data - None, a dict or string, or a list of dicts and strings representing the data body.
            to_json - A boolean, should the responses be returned as JSON blobs
        Returns:
            If multiple requests are made - a list of dicts if to_json, a list of grequest.response otherwise
            If a single request is made, the return is not a list
        Raises:
            InvalidRequestError - if no URL is supplied
        """
        if not urls:
            raise InvalidRequestError('No URL supplied')

        # Break the params into batches of request_params
        request_params = self._zip_request_params(urls, query_params, data)
        batch_of_params = [request_params[pos:pos + self._max_requests] for pos in xrange(0, len(request_params), self._max_requests)]

        # Iteratively issue each batch, applying the rate limiter if necessary
        all_responses = []
        for param_batch in batch_of_params:
            if self._rate_limiter:
                self._rate_limiter.make_calls(num_calls=len(param_batch))

            requests = [self._create_request(verb, url, query_params=query_param, data=datum) for url, query_param, datum in param_batch]
            all_responses.extend(self._wait_for_response(requests, to_json))

        if len(all_responses) == 1:
            return all_responses[0]
        return all_responses

    @classmethod
    def error_handling(cls, fn):
        """Decorator to handle errors while calling out to grequests."""
        def wrapper(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
                return result
            except InvalidRequestError as e:
                exc_type, _, exc_traceback = sys.exc_info()
                sys.stderr.write('[ERROR] {0}\n'.format(exc_type))
                for line in format_list(extract_tb(exc_traceback)):
                    sys.stderr.write(line)

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
        self._all_iocs = sorted(list(self._all_iocs))
        self._suspicious_iocs = sorted(list(self._suspicious_iocs))

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
