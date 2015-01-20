# -*- coding: utf-8 -*-
#
import simplejson
import testify as T
from mock import mock_open
from mock import patch

from osxcollector.output_filters.util.api_cache import ApiCache


class ApiCacheFileIOTest(T.TestCase):

    """Allows for setting and retrieving results of API calls."""

    @T.setup
    def setup_filename(self):
        self._file_name = '/tmp/any_name_will_do'

    def _open_cache(self, initial_contents=None):
        """Creates an ApiCache object, mocking the contents of the cache on disk.

        Args:
                initial_contents: A dict containing the initial contents of the cache
        Returns:
                ApiCache
        """
        if not initial_contents:
            initial_contents = {}

        file_contents = simplejson.dumps(initial_contents)
        mock_read = mock_open(read_data=file_contents)
        with patch('__builtin__.open', mock_read, create=True):
            api_cache = ApiCache(self._file_name)
            return api_cache

    def _close_cache(self, api_cache):
        """Closes an ApiCache and reads the final contents that were written to disk.

        Args:
                api_cache: An ApiCache instance
        Returns:
                A dict representing the contents of the cache that were written back to disk.
        """
        mock_write = mock_open()
        with patch('__builtin__.open', mock_write, create=True) as m:
            api_cache.close()
            T.assert_equal(mock_write.call_count, 1)

            for call in m.mock_calls:
                name, args, kwargs = call
                if '().write' != name:
                    continue

                return simplejson.loads(args[0])
        return None

    def test_create_cache(self):
        initial_contents = {
            'banana': {
                'apple': ['pear', 'panda'],
                'sumo': False,
                'rebel_base_count': 42
            },
            'skiddo': 'Fo Sure',
            'pi': 3.1415
        }

        api_cache = self._open_cache(initial_contents)
        final_contents = self._close_cache(api_cache)
        T.assert_equal(initial_contents, final_contents)

    def test_persist_objects(self):
        contents_to_load = {
            'api1': {
                'key1': 'value1',
                'key2': 11,
                        'key3': {'some': 'dict'},
                        'key4': ['a', 'list']
            },
            'api2': {
                'key1': 'value42',
                'key4': 'lavash bread'
            }
        }

        # Open an empty cache
        api_cache = self._open_cache()

        # Load the cache
        for api_name in contents_to_load.keys():
            for key in contents_to_load[api_name]:
                api_cache.cache_value(api_name, key, contents_to_load[api_name][key])

        # Verify the cache
        for api_name in contents_to_load.keys():
            for key in contents_to_load[api_name]:
                expected_val = contents_to_load[api_name][key]
                actual_val = api_cache.lookup_value(api_name, key)
                T.assert_equal(expected_val, actual_val)

        # Close the cache
        final_contents = self._close_cache(api_cache)
        T.assert_equal(contents_to_load, final_contents)
