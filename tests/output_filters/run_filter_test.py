# -*- coding: utf-8 -*-
from contextlib import nested
from StringIO import StringIO

import simplejson
import testify as T
from mock import patch
from osxcollector.output_filters.base_filters.output_filter import run_filter

DEFAULT_CONFIG = {
    'domain_whitelist': {
        'blacklist_name': 'domain_whitelist',
        'blacklist_keys': ['osxcollector_domains'],
        'blacklist_file_path': '/tmp/domain_whitelist.txt',
        'blacklist_is_domains': True,
        'blacklist_is_regex': True
    }
}

WHITELIST_FILE_CONTENTS = [
    'example.com',
    'example.org',
    'example.net'
]


def run_filter_test(create_filter, input_blobs=None,
                    expected_output_blobs=None, config_initial_contents=None, api_cache_initial_contents=None,
                    blacklist_file_contents=None):
    """Mocks out stdin, stdout, config, and api_cache then runs input lines through an OutputFilter.

    Args:
        create_filter: A callable that returns an OutputFilter.
        input_blobs: An array of dicts to pass to OutputFilter. These will be serialized into strings and passed as stdin.
        expected_output_blobs: An array of dicts the output of the OutputFilter must match.
        config_initial_contents: A dict of config.
        api_cache_initial_contents: A dict of config.
        blacklist_file_contents: An enumerable with contents of a blacklist file.
    """
    if not input_blobs:
        input_blobs = []
    input_lines = '\n'.join([simplejson.dumps(blob) for blob in input_blobs])

    if not config_initial_contents:
        config_initial_contents = DEFAULT_CONFIG
    if not api_cache_initial_contents:
        api_cache_initial_contents = {}
    if not blacklist_file_contents:
        blacklist_file_contents = WHITELIST_FILE_CONTENTS

    with nested(
        patch('sys.stdin', StringIO(input_lines)),
        patch('sys.stdout', new_callable=StringIO),
        patch('osxcollector.output_filters.util.config._read_config', return_value=config_initial_contents),
        patch('osxcollector.output_filters.util.api_cache.ApiCache._read_cache_from_file', return_vale=api_cache_initial_contents),
        patch('osxcollector.output_filters.util.blacklist.Blacklist._read_blacklist_file_contents', return_value=blacklist_file_contents)
    ) as (
        mock_stdin,
        mock_stdout,
        mock_config,
        mock_api_cache,
        mock_blacklist_file
    ):
        output_filter = create_filter()
        run_filter(output_filter)
        output_lines = [line for line in mock_stdout.getvalue().split('\n') if len(line)]
        output_blobs = [simplejson.loads(line) for line in output_lines]

        if expected_output_blobs:
            T.assert_equal(len(output_blobs), len(expected_output_blobs))

            for expected_blob, actual_blob in zip(expected_output_blobs, output_blobs):
                T.assert_equal(expected_blob, actual_blob)

        return output_blobs


def sort_for_comparison(val):
    if isinstance(val, list):
        return sorted(val)
    elif isinstance(val, dict):
        return sort_dict(val)
    else:
        return val


def sort_dict(blob):
    for key in blob.keys():
        val = blob[key]
        if isinstance(val, list):
            blob[key] = sorted(val)
        elif isinstance(val, dict):
            blob[key] = sort_dict(val)
    return blob


def assert_key_added_to_blob(added_key, expected_values, input_blobs, output_blobs):
    """Verifies that a single key has been added to each input_blob with an expected value.

    Asserts that effectively:
    output_blobs = [input_blob.update(key=expected_value) for input_blob, expected_value in zip(expected_values, input_blobs)]

    Args:
        added_key: The name of the key that should have been added.
        expected_values: A list containing the expected value of the key for each input_blob
        input_blobs: A list of dicts that were the initial input.
        output_blobs: A list of dicts that are the output.
    """

    actual_values = list(blob.get(added_key, None) for blob in output_blobs)
    for actual, expected in zip(actual_values, expected_values):
        T.assert_equal(sort_for_comparison(actual), sort_for_comparison(expected))

    # Minus the added key, the input should be unchanged
    for input_blob, output_blob in zip(input_blobs, output_blobs):
        if added_key in output_blob:
            del output_blob[added_key]
        T.assert_equal(input_blob, output_blob)
