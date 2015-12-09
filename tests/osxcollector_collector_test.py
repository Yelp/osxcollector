# -*- coding: utf-8 -*-
import contextlib

import mock
import testify as T

from osxcollector.osxcollector import Collector
from osxcollector.osxcollector import HomeDir
from osxcollector.osxcollector import Logger


class CollectorTestCase(T.TestCase):

    @T.setup_teardown
    def setup_mock_log_dict(self):
        # There is one user, named test
        homedirs = [HomeDir('test', '/Users/test')]
        self.expected_file_info = {
            'md5': '8675309',
            'sha1': 'babababa',
            'sha2': '11'
        }
        with contextlib.nested(
            mock.patch.object(Logger, 'log_dict'),
            mock.patch('osxcollector.osxcollector._get_homedirs', autospec=True, return_value=homedirs),
            mock.patch('osxcollector.osxcollector._get_file_info', autospec=True, return_value=self.expected_file_info)
        ) as (self.mock_log_dict, self.mock_get_homedirs, self.mock_get_file_info):
            self.collector = Collector()
            yield

    def test_log_items_in_plist(self):
        plist = {
            'system': {
                'name': ['os x']
            },
            'version': {
                'minor': '3'
            }
        }

        self.collector._log_items_in_plist(plist, 'system.name')
        self.mock_log_dict.assert_called_with('os x')

    def _really_expected_file_info(self, expected):
        really_expected = {}
        really_expected.update(expected)
        really_expected.update(self.expected_file_info)
        return really_expected

    def _test_log_launch_agents(self, dir_path, expected):
        expected = self._really_expected_file_info(expected)

        self.collector._log_launch_agents(dir_path)
        self.mock_log_dict.assert_called_with(expected)

    def test_log_launch_agents_just_program_no_arguments(self):
        # ProgramArguments value contains only program name
        expected = {
            'label': 'com.apple.csuseragent',
            'program': '/System/Library/CoreServices/CSUserAgent',
            'osxcollector_plist': 'tests/data/launch_agents/csuseragent/csuseragent.plist'
        }
        self._test_log_launch_agents('tests/data/launch_agents/csuseragent/', expected)

    def test_log_launch_agents_program(self):
        # no ProgramArguments, program name is under Program key in plist
        expected = {
            'label': 'com.apple.appleseed.seedusaged',
            'program': '/System/Library/CoreServices/Feedback Assistant.app/Contents/Library/LaunchServices/seedusaged',
            'osxcollector_plist': 'tests/data/launch_agents/seedusaged/seedusaged.plist'
        }
        self._test_log_launch_agents('tests/data/launch_agents/seedusaged/', expected)

    def test_log_launch_agents_program_and_arguments(self):
        # ProgramArguments value contains both program name arguments
        expected = {
            'label': 'com.apple.VoiceOver',
            'program': '/System/Library/CoreServices/VoiceOver.app/Contents/MacOS/VoiceOver',
            'arguments': ['launchd', '-s'],
            'osxcollector_plist': 'tests/data/launch_agents/voice_over/com.apple.VoiceOver.plist'
        }
        self._test_log_launch_agents('tests/data/launch_agents/voice_over/', expected)

    def test_log_packages_in_dir(self):
        expected = {
            'osxcollector_plist_path': 'tests/data/packages/Digital Hub Scripting.osax/Contents/Info.plist',
            'osxcollector_bundle_id': 'com.apple.osax.digihub'
        }
        expected = self._really_expected_file_info(expected)

        self.collector._log_packages_in_dir('tests/data/packages/')
        self.mock_log_dict.assert_called_with(expected)

    def test_log_startup_items(self):
        list_of_files_in_dir = ['StartupParameters.plist']
        plist = {
            'Provides': ['test_service']
        }
        with contextlib.nested(
            mock.patch('os.path.isdir', autospec=True, return_value=True),
            mock.patch('osxcollector.osxcollector.listdir', autospec=True, return_value=list_of_files_in_dir),
            mock.patch.object(Collector, '_read_plist', autospec=True, return_value=plist)
        ):
            self.collector._log_startup_items('test_dir')
            self.mock_log_dict.assert_called_with(self.expected_file_info)

    def test_log_user_login_items(self):
        plist_path = '/Users/test/Library/Preferences/com.apple.loginitems.plist'
        login_item = {
            'Name': 'test-login-item'
        }
        plist = {
            'SessionItems': {
                'CustomListItems': [login_item]
            }
        }
        with mock.patch.object(Collector, '_read_plist', autospec=True, return_value=plist) as mock_read_plist:
            self.collector._log_user_login_items()

            mock_read_plist.assert_called_with(self.collector, plist_path)
            self.mock_log_dict.assert_called_with(login_item)

    def test_collect_accounts_recent_items(self):
        plist_path = '/Users/test/Library/Preferences/com.apple.recentitems.plist'
        plist = {
            'RecentServers': {
                'CustomListItems': [
                    {'Name': 'presidio'},
                    {'Name': 'marina'},
                    {'Name': 'sunset'}
                ]
            },
            'RecentDocuments': {
                'CustomListItems': [
                    {'Name': 'russian_hill.jpg'},
                    {'Name': 'nob_hill.jpg'},
                    {'Name': 'rincon_hill.jpg'}
                ]
            },
            'RecentApplications': {
                'CustomListItems': [
                    {'Name': 'Golden Gate Park'},
                    {'Name': 'Glen Park'},
                    {'Name': 'Jordan Park'}
                ]
            },
            'Hosts': {
                'CustomListItems': [
                    {'Name': 'South of Market', 'URL': 'afp://sfo/soma'},
                    {'Name': 'Financial District', 'URL': 'afp://sfo/fidi'},
                    {'Name': 'North Beach', 'URL': 'afp://sfo/nobe'}
                ]
            }
        }
        recents = [
            {'server_name': 'presidio'},
            {'server_name': 'marina'},
            {'server_name': 'sunset'},
            {'document_name': 'russian_hill.jpg'},
            {'document_name': 'nob_hill.jpg'},
            {'document_name': 'rincon_hill.jpg'},
            {'application_name': 'Golden Gate Park'},
            {'application_name': 'Glen Park'},
            {'application_name': 'Jordan Park'},
            {'host_name': 'South of Market', 'host_url': 'afp://sfo/soma'},
            {'host_name': 'Financial District', 'host_url': 'afp://sfo/fidi'},
            {'host_name': 'North Beach', 'host_url': 'afp://sfo/nobe'}
        ]
        with mock.patch.object(Collector, '_read_plist', autospec=True, return_value=plist) as mock_read_plist:
            self.collector._collect_accounts_recent_items()

            mock_read_plist.assert_called_with(self.collector, plist_path)
            for recent in recents:
                self.mock_log_dict.assert_any_call(recent)

    def test_read_plist_non_existing(self):
        plist = self.collector._read_plist('tests/data/plists/non_existing.plist')
        T.assert_equals({}, plist)
        self.mock_log_dict.assert_not_called()

    def assert_read_plist_parse_error(self, plist_path):
        error = 'Unable to parse plist: [The data couldn\xe2\x80\x99t be read because it isn\xe2\x80\x99t in the correct format.].' \
            + ' plist_path[{0}]'.format(plist_path)
        expected_log = {
            'osxcollector_error': error
        }
        plist = self.collector._read_plist(plist_path)
        T.assert_equals({}, plist)
        self.mock_log_dict.assert_called_once_with(expected_log)

    def test_read_plist_invalid_format(self):
        plist_path = 'tests/data/plists/invalid_format.plist'
        self.assert_read_plist_parse_error(plist_path)

    def test_read_plist_empty(self):
        plist_path = 'tests/data/plists/empty.plist'
        self.assert_read_plist_parse_error(plist_path)
