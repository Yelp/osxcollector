# -*- coding: utf-8 -*-
#
# Utilities for dealing with HTTP requests
#
# RateLimiter helps to only make a certain number of calls per second.
# MultiRequest wraps grequests and issues multiple requests at once with an easy to use interface.
#
import sys
import time
from collections import namedtuple

import grequests
from osxcollector.output_filters.exceptions import InvalidRequestError
from osxcollector.output_filters.util.error_messages import write_error_message
from osxcollector.output_filters.util.error_messages import write_exception


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
        return self._multi_request(MultiRequest._VERB_GET, urls, query_params, None, to_json=to_json)

    def multi_post(self, urls, query_params=None, data=None, to_json=True, send_as_file=False):
        """Issue multiple POST requests.

        Args:
            urls - A string URL or list of string URLs
            query_params - None, a dict, or a list of dicts representing the query params
            data - None, a dict or string, or a list of dicts and strings representing the data body.
            to_json - A boolean, should the responses be returned as JSON blobs
            send_as_file - A boolean, should the data be sent as a file.
        Returns:
            a list of dicts if to_json is set of grequest.response otherwise.
        Raises:
            InvalidRequestError - Can not decide how many requests to issue.
        """
        return self._multi_request(MultiRequest._VERB_POST, urls, query_params, data, to_json=to_json, send_as_file=send_as_file)

    def _create_request(self, verb, url, query_params=None, data=None, send_as_file=False):
        """Helper method to create a single `grequests.post` or `grequests.get`.

        Args:
            verb - MultiRequest._VERB_POST or MultiRequest._VERB_GET
            url - A string URL
            query_params - None or a dict
            data - None or a string or a dict
            send_as_file - A boolean, should the data be sent as a file.
        Returns:
            requests.PreparedRequest
        Raises:
            InvalidRequestError - if an invalid verb is passed in.
        """
        if MultiRequest._VERB_POST == verb:
            if not send_as_file:
                return grequests.post(url, headers=self._default_headers, params=query_params, data=data, timeout=self._req_timeout)
            else:
                files = {'file': data}
                return grequests.post(url, headers=self._default_headers, params=query_params, files=files, timeout=self._req_timeout)
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
                write_error_message('url[{0}] status_code[{1}]'.format(response.request.url, response.status_code))

            # TODO - Add an option for printing this
            sys.stderr.write(response.request.url)
            sys.stderr.write('\n')

            if to_json:
                all_responses.append(response.json())
            else:
                all_responses.append(response)

        return all_responses

    def _multi_request(self, verb, urls, query_params, data, to_json=True, send_as_file=False):
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

            requests = []
            for url, query_param, datum in param_batch:
                requests.append(self._create_request(verb, url, query_params=query_param, data=datum, send_as_file=send_as_file))

            all_responses.extend(self._wait_for_response(requests, to_json))

        return all_responses

    def post_file(self, url, file, to_json=True):
        request = self._create_request(MultiRequest._VERB_POST, url)
        return request

    @classmethod
    def error_handling(cls, fn):
        """Decorator to handle errors while calling out to grequests."""
        def wrapper(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
                return result
            except InvalidRequestError as e:
                write_exception(e)

                if hasattr(e, 'request'):
                    write_error_message('request {0}'.format(repr(e.request)))
                if hasattr(e, 'response'):
                    write_error_message('response {0}'.format(repr(e.response)))

                raise e
        return wrapper
