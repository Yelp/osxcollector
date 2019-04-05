#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  OS X Collector
#  This work is licensed under the GNU General Public License
#  This work is a derivation of https://github.com/jipegit/OSXAuditor
#
#  Gathers information from plists, sqlite DBs, and the local file system to
#  get information for analyzing a malware infection.
#
#  Output to stdout is JSON.  Each line contains a key 'osxcollector_section' which
#  helps identify the line.  Many lines contain a key 'osxcollector_subsection' to
#  further filter output lines.
#
#  Fatal errors are written to stderr.  They can also be found in the JSON output as lines
#  with a key 'osxcollector_error'.
#
#  Non-fatal errors are only written to stderr when the --debug flag is passed to the script.
#  They can also be found in the JSON output as lines with a key 'osxcollector_warn'
#
from __future__ import absolute_import

import base64
import calendar
import os
import shutil
import struct
import sys
from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime
from datetime import timedelta
from functools import partial
from hashlib import md5
from hashlib import sha1
from hashlib import sha256
from json import dumps
from json import loads
from numbers import Number
from sqlite3 import connect
from sqlite3 import OperationalError
from traceback import extract_tb

import Foundation
import macholib.MachO
from xattr import getxattr

from osxcollector import __version__

ROOT_PATH = '/'
"""Global root path to build all further paths off of"""

DEBUG_MODE = False
"""Global debug mode flag for whether to enable breaking into pdb"""


def debugbreak():
    """Break in debugger if global DEBUG_MODE is set"""
    global DEBUG_MODE

    if DEBUG_MODE:
        import pdb
        pdb.set_trace()


HomeDir = namedtuple('HomeDir', ['user_name', 'path'])
"""A simple tuple for storing info about a user"""


def _get_homedirs():
    """Return a list of HomeDir objects

    Takes care of filtering out '.'

    Returns:
        list of HomeDir
    """
    homedirs = []
    users_dir_path = pathjoin(ROOT_PATH, 'Users')
    for user_name in listdir(users_dir_path):
        if not user_name.startswith('.'):
            homedirs.append(HomeDir(user_name, pathjoin(ROOT_PATH, 'Users', user_name)))
    return homedirs


def listdir(dir_path):
    """Safe version of os.listdir will always return an enumerable value

    Takes care of filtering out known useless dot files.

    Args:
        dir_path: str path of directory to list
    Returns:
        list of str
    """
    if not os.path.isdir(dir_path):
        return []

    ignored_files = ['.DS_Store', '.localized']
    return [val for val in os.listdir(dir_path) if val not in ignored_files]


def _relative_path(path):
    """Strips leading slash from a path.

    Args:
        path - a file path
    Returns:
        string
    """
    if path.startswith('/'):
        return path[1:]
    return path


def pathjoin(path, *args):
    """Version of os.path.join that assumes every argument after the first is a relative path

    Args:
        path: The first path part
        args: A list of further paths
    Returns:
        string of joined paths
    """
    if args:
        normed_args = [_relative_path(arg) for arg in args]
        return os.path.join(path, *normed_args)
    else:
        return os.path.join(path)


def _hash_file(file_path):
    """Return the md5, sha1, sha256 hash of a file.

    Args:
        file_path: str path of file to hash
    Returns:
        list of 3 hex strings.  Empty strings on failure.
    """
    hashers = [
        md5(),
        sha1(),
        sha256(),
    ]

    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(partial(f.read, 1024 * 1024), ''):
                for hasher in hashers:
                    hasher.update(chunk)

            return [hasher.hexdigest() for hasher in hashers]
    except Exception:
        debugbreak()
        return ['', '', '']


DATETIME_2001 = datetime(2001, 1, 1)
"""Constant to use for converting timestamps to strings"""
DATETIME_1970 = datetime(1970, 1, 1)
"""Constant to use for converting timestamps to strings"""
DATETIME_1601 = datetime(1601, 1, 1)
"""Constant to use for converting timestamps to strings"""
MIN_YEAR = 2004


def _timestamp_errorhandling(func):
    """Decorator to handle timestamps that are less than MIN_YEAR or after the current date are invalid"""
    def wrapper(*args, **kwargs):
        try:
            dt = func(*args, **kwargs)
            tomorrow = datetime.now() + timedelta(days=1)  # just in case of some timezone issues
            if dt.year < MIN_YEAR or dt > tomorrow:
                return None
            return dt
        except Exception:
            return None

    return wrapper


def _convert_to_local(func):
    '''UTC to local time conversion
    source: http://feihonghsu.blogspot.com/2008/02/converting-from-local-time-to-utc.html
    '''
    def wrapper(*args, **kwargs):
        dt = func(*args, **kwargs)
        return datetime.fromtimestamp(calendar.timegm(dt.timetuple()))

    return wrapper


@_timestamp_errorhandling
@_convert_to_local
def _seconds_since_2001_to_datetime(seconds):
    return DATETIME_2001 + timedelta(seconds=seconds)


@_timestamp_errorhandling
@_convert_to_local
def _seconds_since_epoch_to_datetime(seconds):
    """Converts timestamp to datetime assuming the timestamp is expressed in seconds since epoch"""
    return DATETIME_1970 + timedelta(seconds=seconds)


@_timestamp_errorhandling
@_convert_to_local
def _microseconds_since_epoch_to_datetime(microseconds):
    return DATETIME_1970 + timedelta(microseconds=microseconds)


@_timestamp_errorhandling
@_convert_to_local
def _microseconds_since_1601_to_datetime(microseconds):
    return DATETIME_1601 + timedelta(microseconds=microseconds)


def _value_to_datetime(val):
    # Try various versions of converting a number to a datetime.
    # Ordering is important as a timestamp may be "valid" with multiple different conversion algorithms
    # but it won't necessarily be the correct timestamp
    if isinstance(val, basestring):
        try:
            val = float(val)
        except Exception:
            return None

    return _microseconds_since_epoch_to_datetime(val) \
        or _microseconds_since_1601_to_datetime(val) \
        or _seconds_since_epoch_to_datetime(val) \
        or _seconds_since_2001_to_datetime(val)


def _datetime_to_string(dt):
    try:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        debugbreak()
        return None


ATTR_KMD_ITEM_WHERE_FROMS = 'com.apple.metadata:kMDItemWhereFroms'
ATTR_QUARANTINE = 'com.apple.quarantine'


def _get_where_froms(file_path):
    return _get_extended_attr(file_path, ATTR_KMD_ITEM_WHERE_FROMS)


def _get_quarantines(file_path):
    return _get_extended_attr(file_path, ATTR_QUARANTINE)


def _get_extended_attr(file_path, attr):
    """Get extended attributes from a file, returns an array of strings or None if no value is set.

    Inspired by https://gist.github.com/dunhamsteve/2889617

    Args:
        file_path: str path of file to examine
        attr: key of the attribute to retrieve
    Returns:
        a list of strings or None
    """
    try:
        xattr_val = getxattr(file_path, attr)
        if xattr_val.startswith('bplist'):
            try:
                plist_array, _, plist_error = Foundation.NSPropertyListSerialization.propertyListWithData_options_format_error_(
                    buffer(xattr_val), 0, None, None,
                )
                if plist_error:
                    Logger.log_error(message='plist de-serialization error: {0}'.format(plist_error))
                    return None
                return list(plist_array)
            except Exception as deserialize_plist_e:
                Logger.log_exception(deserialize_plist_e, message='_get_extended_attr failed on {0} for {1}'.format(file_path, attr))
        else:
            return [xattr_val]
    except KeyError:
        pass  # ignore missing key in xattr
    except IOError:
        pass  # ignore not found attribute
    return None


def _get_file_info(file_path, log_xattr=False):
    """Gather info about a file including hash and dates

    Args:
        file_path: str path of file to hash
        log_xattr: boolean whether to log extended attributes of a file
    Returns:
        dict with key ['md5', 'sha1', 'sha2', file_path', 'mtime', 'ctime']
    """
    md5_hash, sha1_hash, sha2_hash = '', '', ''
    atime = ''
    mtime = ''
    ctime = ''
    extra_data_check = ''
    extra_data_found = False

    if os.path.isfile(file_path):
        atime = _datetime_to_string(datetime.fromtimestamp(os.path.getatime(file_path)))
        mtime = _datetime_to_string(datetime.fromtimestamp(os.path.getmtime(file_path)))
        ctime = _datetime_to_string(datetime.fromtimestamp(os.path.getctime(file_path)))
        md5_hash, sha1_hash, sha2_hash = _hash_file(file_path)

        # check for extradata
        try:
            extra_data_result = str(kyphosis(file_path, False).extra_data)
            if extra_data_result == '{}':
                extra_data_check = ''
            else:
                extra_data_check = base64.b64encode(extra_data_result)
                extra_data_found = True
        except Exception:
            extra_data_check = ''

        file_info = {
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha2': sha2_hash,
            'file_path': file_path,
            'atime': atime,
            'mtime': mtime,
            'ctime': ctime,
            'extra_data_check': extra_data_check,
            'extra_data_found': extra_data_found,
        }

        if log_xattr:
            where_from = _get_where_froms(file_path)
            if where_from:
                file_info['xattr-wherefrom'] = where_from

            quarantines = _get_quarantines(file_path)
            if quarantines:
                file_info['xattr-quarantines'] = quarantines

        return file_info

    return {}


def _normalize_val(val, key=None):
    """Transform a value read from SqlLite or a plist into a string

    Special case handling deals with things derived from basestring, buffer, or numbers.Number

    Args:
        val: A value of any type
        key: The key associated with the value.  Will attempt to convert timestamps to a date
        based on the key name
    :returns: A string
    """
    # If the key hints this is a timestamp, try to use some popular formats
    if key and any([hint in key.lower() for hint in ['time', 'utc', 'date', 'accessed']]):
        ts = _value_to_datetime(val)
        # Known timestamp keys with values not conforming to heuristics are mapped to a default timestamp
        if not ts and key in ['last_access_time', 'expires_utc', 'date_created', 'end_time']:
            ts = datetime.fromtimestamp(1)
        if ts:
            return _datetime_to_string(ts)

    try:
        if isinstance(val, basestring):
            try:
                # Firefox history entries contain reversed host name
                # while scope value in webapps_store entries also have it suffixed
                # by protocol and port number, e.g. "moc.elpmaxe.www.:http:80"
                if key in ['rev_host', 'scope']:
                    val = val.split(':')[0][::-1]
                return unicode(val).decode(encoding='utf-8', errors='ignore')
            except UnicodeEncodeError:
                return val
        elif isinstance(val, buffer):
            # Not all buffers will contain text so this is expected to fail
            try:
                return unicode(val).decode(encoding='utf-16le', errors='ignore')
            except Exception:
                return repr(val)
        elif isinstance(val, Number):
            return val
        elif isinstance(val, Foundation.NSData):
            return '<NSData bytes:{0}>'.format(val.length())
        elif isinstance(val, Foundation.NSArray):
            return [_normalize_val(stuff) for stuff in val]
        elif isinstance(val, Foundation.NSDictionary) or isinstance(val, dict):
            return dict([(k, _normalize_val(val.get(k), k)) for k in val.keys()])
        elif isinstance(val, Foundation.NSDate):
            # NSDate could have special case handling
            return repr(val)
        elif not val:
            return ''
        else:
            debugbreak()
            return repr(val)
    except Exception as normalize_val_e:
        to_print = '[ERROR] _normalize_val {0}\n'.format(repr(normalize_val_e))
        sys.stderr.write(to_print)

        debugbreak()
        return repr(val)


def _decode_error_description(error):
    """Decodes error description retrieved from the native NSError format.

    Args:
        error (NSError): object representing error in native Objective-C format
    """
    cfstring = Foundation.CFErrorCopyDescription(error)
    return cfstring.encode('utf-8', 'ignore')


class DictUtils(object):

    """A set of method for manipulating dictionaries."""

    @classmethod
    def _link_path_to_chain(cls, path):
        """Helper method for get_deep

        Args:
            path: A str representing a chain of keys separated '.' or an enumerable set of strings
        Returns:
            an enumerable set of strings
        """
        if path == '':
            return []
        elif type(path) in (list, tuple, set):
            return path
        else:
            return path.split('.')

    @classmethod
    def _get_deep_by_chain(cls, x, chain, default=None):
        """Grab data from a dict using a ['key1', 'key2', 'key3'] chain param to do deep traversal.

        Args:
            x: A dict
            chain: an enumerable set of strings
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        if chain == []:
            return default
        try:
            for link in chain:
                try:
                    x = x[link]
                except (KeyError, TypeError):
                    x = x[int(link)]
        except (KeyError, TypeError, ValueError):
            x = default
        return x

    @classmethod
    def get_deep(cls, x, path='', default=None):
        """Grab data from a dict using a 'key1.key2.key3' path param to do deep traversal.

        Args:
            x: A dict
            path: A 'deep path' to retrieve in the dict
            default: A value to return if the path can not be found
        Returns:
            The value of the key or default
        """
        chain = cls._link_path_to_chain(path)
        return cls._get_deep_by_chain(x, chain, default=default)


class Logger(object):

    """Logging class writes JSON to stdout and stderr

    Additionally, the Logger allows for "extra" key/value pairs to be set.  These will then
    be tacked onto each line logged.  Use the Logger.Extra context manager to set an "extra".

    .. code-block:: python
        with Logger.Extra(extra_key, val):
            # Everything logged in this context will have {'extra_key': val} inserted into output
    """

    output_file = sys.stdout
    # File to write standard output to

    lines_written = 0
    # Counter of lines of standard output written

    @classmethod
    def set_output_file(cls, output_file):
        cls.output_file = output_file

    @classmethod
    def log_dict(cls, record):
        """Splats out a JSON blob to stdout.

        Args:
            record: a dict of data
        """
        record.update(Logger.Extra.extras)
        try:
            cls.output_file.write(dumps(record))
            cls.output_file.write('\n')
            cls.output_file.flush()
            cls.lines_written += 1
        except Exception as e:
            debugbreak()
            cls.log_exception(e)

    @classmethod
    def log_warning(cls, message):
        """Writes a warning message to JSON output and optionally splats a string to stderr if DEBUG_MODE.

        Args:
            message: String with a warning message
        """
        global DEBUG_MODE

        cls.log_dict({'osxcollector_warn': message})
        if DEBUG_MODE:
            sys.stderr.write('[WARN] ')
            sys.stderr.write(message)
            sys.stderr.write(' - {0}\n'.format(repr(Logger.Extra.extras)))

    @classmethod
    def log_error(cls, message):
        """Writes a warning message to JSON output and to stderr.

        Args:
            message: String with a warning message
        """
        cls.log_dict({'osxcollector_error': message})
        sys.stderr.write('[ERROR] ')
        sys.stderr.write(message)
        sys.stderr.write(' - {0}\n'.format(repr(Logger.Extra.extras)))

    @classmethod
    def log_exception(cls, e, message=''):
        """Splat out an Exception instance as a warning

        Args:
            e: An instance of an Exception
            message: a str message to log with the Exception
        """
        exc_type, _, exc_traceback = sys.exc_info()

        to_print = '{0} {1} {2} {3}'.format(message, e.message or '', exc_type, extract_tb(exc_traceback))
        cls.log_error(to_print)

    class Extra(object):

        """A context class for adding additional params to be logged with every line written by Logger"""

        extras = {}
        # Class level dict for storing extras

        def __init__(self, key, val):
            self.key = key
            self.val = val

        def __enter__(self):
            global DEBUG_MODE
            Logger.Extra.extras[self.key] = self.val

            if DEBUG_MODE:
                sys.stderr.write(dumps({self.key: self.val}))
                sys.stderr.write('\n')

        def __exit__(self, type, value, traceback):
            del Logger.Extra.extras[self.key]


PATH_ENVIRONMENT_NAME = 'PATH'


class Collector(object):

    """Examines plists, sqlite dbs, and hashes files to gather info useful for analyzing a malware infection"""

    def __init__(self):
        # A list of the names of accounts with admin privileges
        self.admins = []

        # A list of HomeDir used when finding per-user data
        self.homedirs = _get_homedirs()

    def collect(self, section_list=None):
        """The primary public method for collecting data.

        Args:
            section_list: OPTIONAL A list of strings with names of sections to collect.
        """

        sections = [
            ('version', self._version_string),
            ('system_info', self._collect_system_info),
            ('kext', self._collect_kext),
            ('startup', self._collect_startup),
            ('applications', self._collect_applications),
            ('quarantines', self._collect_quarantines),
            ('downloads', self._collect_downloads),
            ('chrome', self._collect_chrome),
            ('firefox', self._collect_firefox),
            ('safari', self._collect_safari),
            ('accounts', self._collect_accounts),
            ('mail', self._collect_mail),
            ('executables', self._collect_binary_names_in_path),
            ('full_hash', self._collect_full_hash),
        ]

        # If no section_list was specified, collect everything but the 'full_hash' section
        if not section_list:
            section_list = [s[0] for s in sections[:-1]]

        for section_name, collection_method in sections:
            with Logger.Extra('osxcollector_section', section_name):
                if section_list and section_name not in section_list:
                    continue

                try:
                    collection_method()
                except Exception as section_e:
                    debugbreak()
                    Logger.log_exception(section_e, message='failed section')

    def _is_fde_enabled(self):
        """Gathers the Full Disc Encryption status of the system."""

        fde_status = os.popen('fdesetup status').read()

        if 'On' in fde_status:
            return True
        else:
            return False

    def _foreach_homedir(func):
        """A decorator to ensure a method is called for each user's homedir.

        As a side-effect, this adds the 'osxcollector_username' key to Logger output.
        """

        def wrapper(self, *args, **kwargs):
            for homedir in self.homedirs:
                with Logger.Extra('osxcollector_username', homedir.user_name):
                    try:
                        func(self, *args, homedir=homedir, **kwargs)
                    except Exception as e:
                        Logger.log_exception(e)

        return wrapper

    def _read_plist(self, plist_path, default=None):
        """Read a plist file and return a dict representing it.

        The return should be suitable for JSON serialization.

        Args:
            plist_path: The path to the file to read.
            default: The value to return on error
        Returns:
            a dict or list. Empty dict on failure.
        """
        if not default:
            default = {}

        if not os.path.isfile(plist_path):
            Logger.log_warning('plist file not found. plist_path[{0}]'.format(plist_path))
            return default

        try:
            plist_nsdata, error = Foundation.NSData.dataWithContentsOfFile_options_error_(
                plist_path, Foundation.NSUncachedRead, None,
            )
            if error:
                error_description = _decode_error_description(error)
                Logger.log_error('Unable to read plist: [{0}]. plist_path[{1}]'.format(error_description, plist_path))
                return default
            if 0 == plist_nsdata.length():
                Logger.log_warning('Empty plist. plist_path[{0}]'.format(plist_path))
                return default

            plist_dictionary, _, error = Foundation.NSPropertyListSerialization.propertyListWithData_options_format_error_(
                plist_nsdata, Foundation.NSPropertyListMutableContainers, None, None,
            )
            if error:
                error_description = _decode_error_description(error)
                Logger.log_error('Unable to parse plist: [{0}]. plist_path[{1}]'.format(error_description, plist_path))
                return default

            plist = _normalize_val(plist_dictionary)

            # If the output of _read_plist is not a dict or list, things aren't going to work properly. Log an informative error.
            if not isinstance(plist, dict) and not isinstance(plist, list):
                Logger.log_error('plist is wrong type. plist_path[{0}] type[{1}]'.format(plist_path, plist.__class__.__name__))
                return default

            return plist
        except Exception as read_plist_e:
            Logger.log_exception(read_plist_e, message='_read_plist failed on {0}'.format(plist_path))

        return default

    def _log_items_in_plist(self, plist, path, transform=None):
        """Dive into the dict representation of a plist and log all items under a specific path

        Args:
            plist: A dict representation of a plist.
            path: A str which will be passed to get_deep()
            transform: An optional method for transforming each item before logging.
        """
        for item in DictUtils.get_deep(plist, path=path, default=[]):
            try:
                if transform:
                    item = transform(item)
                Logger.log_dict(item)
            except Exception as log_items_in_plist_e:
                Logger.log_exception(log_items_in_plist_e)

    def _log_file_info_for_directory(self, dir_path, recurse=False):
        """Logs file information for every file in a directory.

        Args:
            dir_path: string path to a directory
            recurse: boolean, whether to recurse into child directories
        """
        if not os.path.isdir(dir_path):
            Logger.log_warning('Directory not found {0}'.format(dir_path))
            return

        walker = os.walk(dir_path)
        while True:
            try:
                root, _, file_names = next(walker)
            except StopIteration:
                break

            for file_name in file_names:
                try:
                    file_path = pathjoin(root, file_name)
                    file_info = _get_file_info(file_path, True)
                    Logger.log_dict(file_info)
                except Exception as log_file_info_for_directory_e:
                    Logger.log_exception(log_file_info_for_directory_e)

    @_foreach_homedir
    def _log_user_quarantines(self, homedir):
        """Log the quarantines for a user

        Quarantines is basically the info necessary to show the 'Are you sure you wanna run this?' when
        a user is trying to open a file downloaded from the Internet.  For some more details, checkout the
        Apple Support explanation of Quarantines: http://support.apple.com/kb/HT3662

        Args:
            homedir: A HomeDir
        """

        # OS X >= 10.7
        db_path = pathjoin(homedir.path, 'Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2')
        if not os.path.isfile(db_path):
            # OS X <= 10.6
            db_path = pathjoin(homedir.path, 'Library/Preferences/com.apple.LaunchServices.QuarantineEvents')

        self._log_sqlite_db(db_path)

    def _log_xprotect(self):
        """XProtect adds hash-based malware checking to quarantine files.

        The plist for XProtect is at: /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist

        XProtect also add minimum versions for Internet Plugins. That plist is at:
        /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist
        """
        xprotect_files = [
            'System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist',
            'System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist',
        ]

        for file_path in xprotect_files:
            file_info = _get_file_info(pathjoin(ROOT_PATH, file_path))
            Logger.log_dict(file_info)

    def _should_walk(self, sub_dir_path):
        return any([sub_dir_path.endswith(extension) for extension in ['.app', '.kext', '.osax', 'Contents']])

    def _log_packages_in_dir(self, dir_path):
        """Log the packages in a directory"""
        plist_file = 'Info.plist'

        walk = [(sub_dir_path, file_names) for sub_dir_path, _, file_names in os.walk(dir_path) if self._should_walk(sub_dir_path)]
        for sub_dir_path, file_names in walk:
            if plist_file in file_names:
                if sub_dir_path.endswith('Contents'):
                    cfbundle_executable_path = 'MacOS'
                else:
                    cfbundle_executable_path = ''

            plist_path = pathjoin(sub_dir_path, plist_file)
            plist = self._read_plist(plist_path)
            cfbundle_executable = plist.get('CFBundleExecutable')
            if cfbundle_executable:
                file_path = pathjoin(sub_dir_path, cfbundle_executable_path, cfbundle_executable)
                file_info = _get_file_info(file_path)
                file_info['osxcollector_plist_path'] = plist_path
                file_info['osxcollector_bundle_id'] = plist.get('CFBundleIdentifier', '')
                Logger.log_dict(file_info)

    def _log_startup_items(self, dir_path):
        """Log the startup_item plist and hash its program argument

        Startup items are launched in the final phase of boot.  See more at:
        https://developer.apple.com/library/mac/documentation/macosx/conceptual/bpsystemstartup/chapters/StartupItems.html

        The 'Provides' element of the plist is an array of services provided by the startup item.
        _log_startup_items treats each element of 'Provides' as a the name of a file and attempts to hash it.
        """
        if not os.path.isdir(dir_path):
            Logger.log_warning('Directory not found {0}'.format(dir_path))
            return

        for entry in listdir(dir_path):
            plist_path = pathjoin(dir_path, entry, 'StartupParameters.plist')
            plist = self._read_plist(plist_path)

            try:
                self._log_items_in_plist(plist, 'Provides', transform=lambda x: _get_file_info(pathjoin(dir_path, entry, x)))
            except Exception as log_startup_items_e:
                Logger.log_exception(log_startup_items_e)

    def _log_launch_agents(self, dir_path):
        """Log a LaunchAgent plist and hash the program it runs.

        The plist for a launch agent is described at:
        https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man5/launchd.plist.5.html

        In addition to hashing the program, _log_launch_agents will attempt to look for suspicious program arguments in
        the launch agent.  Check the 'suspicious' key in the output to identify suspicious launch agents.
        """
        if not os.path.isdir(dir_path):
            Logger.log_warning('Directory not found {0}'.format(dir_path))
            return

        for entry in listdir(dir_path):
            plist_path = pathjoin(dir_path, entry)
            plist = self._read_plist(plist_path)

            try:
                program = plist.get('Program', '')
                program_with_arguments = plist.get('ProgramArguments', [])
                if program or len(program_with_arguments):
                    file_path = pathjoin(ROOT_PATH, program or program_with_arguments[0])

                    file_info = _get_file_info(file_path)
                    file_info['label'] = plist.get('Label')
                    file_info['program'] = file_path
                    file_info['osxcollector_plist'] = plist_path
                    if len(program_with_arguments) > 1:
                        file_info['arguments'] = list(program_with_arguments)[1:]
                    Logger.log_dict(file_info)
            except Exception as log_launch_agents_e:
                Logger.log_exception(log_launch_agents_e)

    @_foreach_homedir
    def _log_user_launch_agents(self, homedir):
        path = pathjoin(homedir.path, 'Library/LaunchAgents/')
        self._log_launch_agents(path)

    @_foreach_homedir
    def _log_user_login_items(self, homedir):
        """Log the login items for a user

        Login items are startup items that open automatically when a user logs in.
        They are visible in 'System Preferences'->'Users & Groups'->'Login Items'

        The name of the item is in 'SessionItems.CustomListItems.Name'
        The application to launch is in 'SessionItems.CustomListItems.Alias' but this binary structure is hard to read.
        """

        plist_path = pathjoin(homedir.path, 'Library/Preferences/com.apple.loginitems.plist')
        plist = self._read_plist(plist_path)
        self._log_items_in_plist(plist, 'SessionItems.CustomListItems')

    def _version_string(self):
        """Log the current version of this program (osxcollector)"""
        Logger.log_dict({'osxcollector_version': __version__})

    def _collect_system_info(self):
        """Collect basic info about the system and system logs"""

        # Basic OS info
        sysname, nodename, release, version, machine = os.uname()
        fde = self._is_fde_enabled()
        record = {
            'sysname': sysname,
            'nodename': nodename,
            'release': release,
            'version': version,
            'machine': machine,
            'fde': fde,
        }
        Logger.log_dict(record)

    def _collect_binary_names_in_path(self):
        """Collect the names of executable binaries in the PATH environment"""
        exe_files = []

        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        if PATH_ENVIRONMENT_NAME in os.environ:
            for bin_dir in os.environ[PATH_ENVIRONMENT_NAME].split(os.pathsep):
                for root_dir, dirs, files in os.walk(bin_dir):
                    for the_file in files:
                        file_path = os.path.join(root_dir, the_file)
                        if is_exe(file_path):
                            exe_files.append(file_path)
        Logger.log_dict({'executable_files': exe_files})

    def _collect_startup(self):
        """Log the different LauchAgents and LaunchDaemons"""

        # http://www.malicious-streams.com/article/Mac_OSX_Startup.pdf
        launch_agents = [
            'System/Library/LaunchAgents',
            'System/Library/LaunchDaemons',
            'Library/LaunchAgents',
            'Library/LaunchDaemons',
        ]
        with Logger.Extra('osxcollector_subsection', 'launch_agents'):
            for dir_path in launch_agents:
                self._log_launch_agents(pathjoin(ROOT_PATH, dir_path))
            self._log_user_launch_agents()

        packages = [
            'System/Library/ScriptingAdditions',
            'Library/ScriptingAdditions',
        ]
        with Logger.Extra('osxcollector_subsection', 'scripting_additions'):
            for dir_path in packages:
                self._log_packages_in_dir(pathjoin(ROOT_PATH, dir_path))

        startup_items = [
            'System/Library/StartupItems',
            'Library/StartupItems',
        ]
        with Logger.Extra('osxcollector_subsection', 'startup_items'):
            for dir_path in startup_items:
                self._log_startup_items(pathjoin(ROOT_PATH, dir_path))

        with Logger.Extra('osxcollector_subsection', 'login_items'):
            self._log_user_login_items()

    def _collect_quarantines(self):
        """Log quarantines and XProtect hash-based malware checking definitions
        """
        self._log_user_quarantines()
        self._log_xprotect()

    def _collect_full_hash(self):
        """Hash everything on the drive"""
        self._log_file_info_for_directory(ROOT_PATH)

    @_foreach_homedir
    def _collect_downloads(self, homedir):
        """Hash all users's downloaded files"""

        directories_to_hash = [
            ('downloads', 'Downloads'),
            ('email_downloads', 'Library/Mail Downloads'),
            ('old_email_downloads', 'Library/Containers/com.apple.mail/Data/Library/Mail Downloads'),
        ]

        for subsection_name, path_to_dir in directories_to_hash:
            with Logger.Extra('osxcollector_subsection', subsection_name):
                dir_path = pathjoin(homedir.path, path_to_dir)
                self._log_file_info_for_directory(dir_path)

    def _collect_json_files(self, dir_path):
        """Collect all JSON files in a directory

        Args:
            dir_path: Absolute path to the directory
            """
        if not os.path.isdir(dir_path):
            Logger.log_warning('Directory not found {0}'.format(dir_path))
            return

        json_files = [
            file_name for file_name in listdir(dir_path)
            if file_name.endswith('.json')
        ]
        for file_name in json_files:
            self._log_json_file(dir_path, file_name)

    def _log_json_file(self, dir_path, file_name):
        """Dump a JSON file to a single log line

        Args:
            dir_path: Absolute path to the directory
            file_name: File name
        """
        try:
            with open(pathjoin(dir_path, file_name), 'r') as fp:
                file_contents = fp.read()
                record = loads(file_contents)
                with Logger.Extra('osxcollector_json_file', file_name):
                    Logger.log_dict({'contents': record})

        except Exception as log_json_e:
            Logger.log_exception(
                log_json_e, message='failed _log_json_file dir_path[{0}] file_name[{1}]'.format(dir_path, file_name),
            )

    def _log_sqlite_table(self, table_name, cursor, ignore_keys):
        """Dump a SQLite table

        Args:
            table_name: The name of the table to dump
            cursor: sqlite3 cursor object
            ignore_keys: A list of the keys (column names) to ignore when logging the table.
        """
        with Logger.Extra('osxcollector_table_name', table_name):

            try:
                # Grab the whole table
                cursor.execute('SELECT * from {0}'.format(table_name))
                rows = cursor.fetchall()
                if not len(rows):
                    return

                # Grab the column descriptions
                column_descriptions = [col[0] for col in cursor.description]

                # Splat out each record
                for row in rows:
                    record = dict([(key, _normalize_val(val, key)) for key, val in zip(column_descriptions, row) if key not in ignore_keys])
                    Logger.log_dict(record)

            except Exception as per_table_e:
                Logger.log_exception(per_table_e, message='failed _log_sqlite_table')

    def _raw_log_sqlite_db(self, sqlite_db_path, ignore):
        with connect(sqlite_db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * from sqlite_master WHERE type = "table"')
            tables = cursor.fetchall()
            table_names = [table[2] for table in tables]

            for table_name in table_names:
                ignore_keys = ignore.get(table_name, [])
                self._log_sqlite_table(table_name, cursor, ignore_keys)

    def _log_sqlite_db(self, sqlite_db_path, ignore={}):
        """Dump a SQLite database file as JSON.

        Args:
            sqlite_db_path: The path to the SQLite file
            ignore (optional): The dictionary associating table names
                and keys to ignore when dumping the database
        """
        if not os.path.isfile(sqlite_db_path):
            Logger.log_warning('File not found {0}'.format(sqlite_db_path))
            return

        with Logger.Extra('osxcollector_db_path', sqlite_db_path):

            # Connect and get all table names
            try:
                self._raw_log_sqlite_db(sqlite_db_path, ignore)

            except Exception as connection_e:
                if isinstance(connection_e, OperationalError) and -1 != connection_e.message.find('locked'):
                    shutil.copyfile(sqlite_db_path, '{0}.tmp'.format(sqlite_db_path))
                    self._raw_log_sqlite_db('{0}.tmp'.format(sqlite_db_path), ignore)
                    os.remove('{0}.tmp'.format(sqlite_db_path))

                    Logger.log_warning('{0} was locked. Copied to {0}.tmp & analyzed.'.format(sqlite_db_path))
                else:
                    Logger.log_exception(connection_e, message='failed _log_sqlite_db')

    def _log_sqlite_dbs_for_subsections(
            self, sqlite_dbs, profile_path, ignored_sqlite_keys={},
    ):
        """Dumps SQLite databases for each subsection.

        Args:
            sqlite_dbs: The list of tuples containing subsection name
                and related SQLite database filename
            profile_path: The path to a browser profile to which
                the SQLite database filenames are relative to
            ignored_sqlite_keys: The dictionary containing the mapping
                between the subsection, the SQLite table name and
                the key name, which value should not be dumped
        """
        for subsection_name, db_name in sqlite_dbs:
            with Logger.Extra('osxcollector_subsection', subsection_name):
                ignore = ignored_sqlite_keys.get(subsection_name, {})
                sqlite_db_path = pathjoin(profile_path, db_name)
                self._log_sqlite_db(sqlite_db_path, ignore)

    def _log_directories_of_dbs(
            self, directories_of_dbs, profile_path, ignored_sqlite_keys,
            ignore_db_path=lambda sqlite_db_path: False,
    ):
        """Dumps SQLite databases for each subsection.

        Args:
            directories_of_dbs: The list of tuples containing
                subsection name and related subdirectory for which all
                of the SQLite databases will be dumped
            profile_path: The path to a browser profile to which
                the subdirectories are relative to
            ignored_sqlite_keys: The dictionary containing the mapping
                between the subsection, the SQLite table name and
                the key name, which value should not be dumped
            ignore_db_path (optional): The function which takes
                the SQLite database path and returns True if
                the database file should not be dumped
        """
        for subsection_name, dir_name in directories_of_dbs:
            with Logger.Extra('osxcollector_subsection', subsection_name):
                ignore = ignored_sqlite_keys.get(subsection_name, {})
                dir_path = pathjoin(profile_path, dir_name)
                for db in listdir(dir_path):
                    sqlite_db_path = pathjoin(dir_path, db)
                    if not ignore_db_path(sqlite_db_path):
                        self._log_sqlite_db(sqlite_db_path, ignore)

    @_foreach_homedir
    def _collect_firefox(self, homedir):
        """Log the different SQLite databases in a Firefox profile"""
        global firefox_ignored_sqlite_keys

        all_profiles_path = pathjoin(homedir.path, 'Library/Application Support/Firefox/Profiles')
        if not os.path.isdir(all_profiles_path):
            Logger.log_warning('Directory not found {0}'.format(all_profiles_path))
            return

        # Most useful. See: http://kb.mozillazine.org/Profile_folder_-_Firefox
        for profile_name in listdir(all_profiles_path):
            profile_path = pathjoin(all_profiles_path, profile_name)

            sqlite_dbs = [
                ('cookies', 'cookies.sqlite'),
                ('downloads', 'downloads.sqlite'),
                ('formhistory', 'formhistory.sqlite'),
                ('history', 'places.sqlite'),
                ('signons', 'signons.sqlite'),
                ('permissions', 'permissions.sqlite'),
                ('addons', 'addons.sqlite'),
                ('extension', 'extensions.sqlite'),
                ('content_prefs', 'content-prefs.sqlite'),
                ('health_report', 'healthreport.sqlite'),
                ('webapps_store', 'webappsstore.sqlite'),
            ]

            self._log_sqlite_dbs_for_subsections(
                sqlite_dbs, profile_path, firefox_ignored_sqlite_keys,
            )

            with Logger.Extra('osxcollector_subsection', 'json_files'):
                self._collect_json_files(profile_path)

    @_foreach_homedir
    def _collect_safari(self, homedir):
        """Log the different plist and SQLite databases in a Safari profile"""
        global safari_ignored_sqlite_keys

        profile_path = pathjoin(homedir.path, 'Library/Safari')
        if not os.path.isdir(profile_path):
            Logger.log_warning('Directory not found {0}'.format(profile_path))
            return

        plists = [
            ('downloads', 'Downloads.plist', 'DownloadHistory'),
            ('history', 'History.plist', 'WebHistoryDates'),
            ('extensions', 'Extensions/Extensions.plist', 'Installed Extensions'),
        ]

        for subsection_name, plist_name, key_to_log in plists:
            with Logger.Extra('osxcollector_subsection', subsection_name):
                plist_path = pathjoin(profile_path, plist_name)
                plist = self._read_plist(plist_path)
                self._log_items_in_plist(plist, key_to_log)

        # collect history from SQLite database in History.db
        sqlite_dbs = [
            ('history', 'History.db'),
        ]
        self._log_sqlite_dbs_for_subsections(sqlite_dbs, profile_path)

        directories_of_dbs = [
            ('databases', 'Databases'),
            ('localstorage', 'LocalStorage'),
        ]
        self._log_directories_of_dbs(
            directories_of_dbs, profile_path, safari_ignored_sqlite_keys,
        )

        # collect file info for each extension
        with Logger.Extra('osxcollector_subsection', 'extension_files'):
            dir_path = pathjoin(profile_path, 'Extensions')
            self._log_file_info_for_directory(dir_path)

    @_foreach_homedir
    def _collect_chrome(self, homedir):
        """Log the different files in a Chrome profile"""
        global chrome_ignored_sqlite_keys

        chrome_path = pathjoin(homedir.path, 'Library/Application Support/Google/Chrome')
        if not os.path.isdir(chrome_path):
            Logger.log_warning('Directory not found {0}'.format(chrome_path))
            return

        profile_paths = [pathjoin(chrome_path, subdir) for subdir in os.listdir(chrome_path) if os.path.isdir(os.path.join(chrome_path, subdir)) and os.path.isfile('{0}/{1}/History'.format(chrome_path, subdir))]

        sqlite_dbs = [
            ('history', 'History'),
            ('archived_history', 'Archived History'),
            ('cookies', 'Cookies'),
            ('login_data', 'Login Data'),
            ('top_sites', 'Top Sites'),
            ('web_data', 'Web Data'),
        ]

        directories_of_dbs = [
            ('databases', 'databases'),
            ('local_storage', 'Local Storage'),
        ]

        def ignore_db_path(sqlite_db_path):
            # Files ending in '-journal' are encrypted
            return sqlite_db_path.endswith('-journal') or os.path.isdir(
                sqlite_db_path,
            )

        for profile_path in profile_paths:
            self._log_directories_of_dbs(
                directories_of_dbs, profile_path, chrome_ignored_sqlite_keys,
                ignore_db_path,
            )
            self._log_sqlite_dbs_for_subsections(
                sqlite_dbs, profile_path, chrome_ignored_sqlite_keys,
            )
            with Logger.Extra('osxcollector_subsection', 'preferences'):
                self._log_json_file(profile_path, 'preferences')

    def _collect_kext(self):
        """Log the Kernel extensions"""
        kext_paths = [
            'System/Library/Extensions',
            'Library/Extensions',
        ]

        for kext_path in kext_paths:
            self._log_packages_in_dir(pathjoin(ROOT_PATH, kext_path))

    def _collect_accounts(self):
        """Log users's accounts"""
        accounts = [
            ('system_admins', self._collect_accounts_system_admins),
            ('system_users', self._collect_accounts_system_users),
            ('social_accounts', self._collect_accounts_social_accounts),
            ('recent_items', self._collect_accounts_recent_items),
        ]
        for subsection_name, collector in accounts:
            with Logger.Extra('osxcollector_subsection', subsection_name):
                collector()

    def _collect_accounts_system_admins(self):
        """Log the system admins group db"""
        sys_admin_plist_path = pathjoin(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/groups/admin.plist')
        sys_admin_plist = self._read_plist(sys_admin_plist_path)

        for admin in sys_admin_plist.get('groupmembers', []):
            self.admins.append(admin)
        for admin in sys_admin_plist.get('users', []):
            self.admins.append(admin)

        Logger.log_dict({'admins': self.admins})

    def _collect_accounts_system_users(self):
        """Log the system users db"""
        for user_name in listdir(pathjoin(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/users')):
            if user_name[0].startswith('.'):
                continue

            user_details = {}

            sys_user_plist_path = pathjoin(ROOT_PATH, 'private/var/db/dslocal/nodes/Default/users', user_name)
            sys_user_plist = self._read_plist(sys_user_plist_path)

            user_details['names'] = [{'name': val, 'is_admin': (val in self.admins)} for val in sys_user_plist.get('name', [])]
            user_details['realname'] = [val for val in sys_user_plist.get('realname', [])]
            user_details['shell'] = [val for val in sys_user_plist.get('shell', [])]
            user_details['home'] = [val for val in sys_user_plist.get('home', [])]
            user_details['uid'] = [val for val in sys_user_plist.get('uid', [])]
            user_details['gid'] = [val for val in sys_user_plist.get('gid', [])]
            user_details['generateduid'] = []
            for val in sys_user_plist.get('generateduid', []):
                user_details['generateduid'].append({'name': val, 'is_admin': (val in self.admins)})

            Logger.log_dict(user_details)

    @_foreach_homedir
    def _collect_accounts_social_accounts(self, homedir):
        user_accounts_path = pathjoin(homedir.path, 'Library/Accounts/Accounts3.sqlite')
        self._log_sqlite_db(user_accounts_path)

    @_foreach_homedir
    def _collect_accounts_recent_items(self, homedir):
        """Log users' recent items"""

        recent_items_account_plist_path = pathjoin(homedir.path, 'Library/Preferences/com.apple.recentitems.plist')

        recents_plist = self._read_plist(recent_items_account_plist_path)

        recents = [
            ('server', 'RecentServers'),
            ('document', 'RecentDocuments'),
            ('application', 'RecentApplications'),
            ('host', 'Hosts'),
        ]

        for recent_type, recent_key in recents:
            with Logger.Extra('recent_type', recent_type):
                for recent in DictUtils.get_deep(recents_plist, '{0}.CustomListItems'.format(recent_key), []):
                    recent_details = {'{0}_name'.format(recent_type): recent['Name']}
                    if recent_type == 'host':
                        recent_details['host_url'] = recent['URL']
                    Logger.log_dict(recent_details)

    @_foreach_homedir
    def _collect_user_applications(self, homedir):
        """Hashes installed apps in the user's ~/Applications directory"""
        self._log_packages_in_dir(pathjoin(homedir.path, 'Applications'))

    def _collect_applications(self):
        """Hashes installed apps in and gathers install history"""

        with Logger.Extra('osxcollector_subsection', 'applications'):
            # Hash all files in /Applications
            self._log_packages_in_dir(pathjoin(ROOT_PATH, 'Applications'))
            # Hash all files in ~/Applications
            self._collect_user_applications()

        # Read the installed applications history
        with Logger.Extra('osxcollector_subsection', 'install_history'):
            plist = self._read_plist(pathjoin(ROOT_PATH, 'Library/Receipts/InstallHistory.plist'), default=[])
            for installed_app in plist:
                Logger.log_dict(installed_app)

    @_foreach_homedir
    def _collect_mail(self, homedir):
        """Hashes file in the mail app directories"""
        mail_paths = [
            'Library/Mail',
            'Library/Mail Downloads',
        ]
        for mail_path in mail_paths:
            self._log_file_info_for_directory(pathjoin(homedir.path, mail_path))


class LogFileArchiver(object):

    def archive_logs(self, target_dir_path):
        """Main method for archiving files

        Args:
            target_dir_path: Path the directory files should be archived to
        """
        to_archive = [
            ('private/var/log', 'system.', None),
            ('Library/Logs', None, None),
            ('Library/Logs/DiagnosticReports', None, '.crash'),
        ]

        for log_path, log_file_prefix, log_file_suffix in to_archive:
            log_dir_path = pathjoin(ROOT_PATH, log_path)

            for file_name in listdir(log_dir_path):
                if log_file_prefix and not file_name.startswith(log_file_prefix):
                    continue

                if log_file_suffix and not file_name.endswith(log_file_suffix):
                    continue

                src = pathjoin(log_dir_path, file_name)
                if not os.path.isfile(src):
                    continue

                dst = pathjoin(target_dir_path, file_name)
                try:
                    shutil.copyfile(src, dst)
                except Exception as archive_e:
                    debugbreak()
                    Logger.log_exception(archive_e, message='src[{0}] dst[{1}]'.format(src, dst))

    def compress_directory(self, file_name, output_dir_path, target_dir_path):
        """Compress a directory into a .tar.gz

        Args:
            file_name: The name of the .tar.gz to file to create.  Do not include the extension.
            output_dir_path: The directory to place the output file in.
            target_dir_path: The directory to compress
        """
        try:
            # Zip the whole thing up
            shutil.make_archive(file_name, format='gztar', root_dir=output_dir_path, base_dir=target_dir_path)
        except Exception as compress_directory_e:
            debugbreak()
            Logger.log_exception(compress_directory_e)


class kyphosis():

    def __init__(self, someFile, writeFile=False):

        self.someFile = someFile
        self.extra_data_found = False
        self.supportedfiles = [
            '\xca\xfe\xba\xbe',  # FAT
            '\xcf\xfa\xed\xfe',  # x86
            '\xce\xfa\xed\xfe',   # x86_64
        ]
        # check if macho
        self.dataoff = 0
        self.datasize = 0
        self.beginOffset = 0
        self.endOffset = 0
        self.fat_hdrs = {}
        self.extra_data = {}
        self.writeFile = writeFile

        self.run()

    def run(self):
        if self.check_binary() is not True:
            # print "Submitted file is not a MachO file"
            return None

        self.aFile = macholib.MachO.MachO(self.someFile)

        if self.aFile.fat is None:
            self.find_load_cmds()
            self.check_macho_size()
        else:
            # Fat file
            self.make_soap()

        if self.extra_data_found is True:
            return True
        else:
            return False

    def make_soap(self):
        # process Fat file
        with open(self.someFile, 'r') as self.bin:
            self.bin.read(4)
            ArchNo = struct.unpack('>I', self.bin.read(4))[0]
            for arch in range(ArchNo):
                self.fat_hdrs[arch] = self.fat_header()
            self.end_fat_hdr = self.bin.tell()
            beginning = True
            self.count = 0
            for hdr, value in self.fat_hdrs.iteritems():
                if beginning is True:
                    self.beginOffset = self.end_fat_hdr
                    self.endOffset = value['Offset']
                    self.check_space()
                    self.beginOffset = value['Size'] + value['Offset']
                    beginning = False
                    self.count += 1
                    continue
                self.endOffset = value['Offset']
                self.check_space()
                self.beginOffset = value['Size'] + value['Offset']
                self.count += 1
        # Check end of file
        self.last_entry = self.beginOffset
        self.check_macho_size()

    def check_space(self):
        self.bin.seek(self.beginOffset, 0)
        self.empty_space = self.bin.read(self.endOffset - self.beginOffset)
        if self.empty_space != len(self.empty_space) * '\x00':
            self.extra_data_found = True
            self.extra_data[self.count] = self.empty_space
            if self.writeFile is True:
                print 'Writing to ' + os.path.basename(self.someFile) + '.extra_data_section' + str(self.count)
                with open(os.path.basename(self.someFile) + '.extra_data_section' + str(self.count), 'w') as h:
                    h.write(self.empty_space)

    def fat_header(self):
        header = {}
        header['CPU Type'] = struct.unpack('>I', self.bin.read(4))[0]
        header['CPU SubType'] = struct.unpack('>I', self.bin.read(4))[0]
        header['Offset'] = struct.unpack('>I', self.bin.read(4))[0]
        header['Size'] = struct.unpack('>I', self.bin.read(4))[0]
        header['Align'] = struct.unpack('>I', self.bin.read(4))[0]
        return header

    def check_binary(self):
        with open(self.someFile, 'r') as f:
            self.magicheader = f.read(4)
            if self.magicheader in self.supportedfiles:
                return True

    def find_load_cmds(self):
        for header in self.aFile.headers:
            for command in header.commands:
                if 'dataoff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['dataoff']
                    if 'datassize' in vars(command[1])['_objects_']:
                        self._datasize = vars(command[1])['_objects_']['datassize']
                    else:
                        self._datasize = vars(command[1])['_objects_']['datasize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize
                if 'stroff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['stroff']
                    self._datasize = vars(command[1])['_objects_']['strsize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize
                if 'fileoff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['fileoff']
                    self._datasize = vars(command[1])['_objects_']['filesize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize

        self.last_entry = int(self.datasize + self.dataoff)

    def check_macho_size(self):
        with open(self.someFile, 'r') as f:
            if os.stat(self.someFile).st_size > self.last_entry:
                f.seek(self.last_entry, 0)
                extra_data_end = f.read()
                self.extra_data_found = True
                self.extra_data['extra_data_end'] = extra_data_end
                if self.writeFile is True:
                    print 'Writing to ' + os.path.basename(self.someFile) + '.extra_data_end'
                    with open(os.path.basename(self.someFile) + '.extra_data_end', 'w') as g:
                        g.write(extra_data_end)


def main():

    global DEBUG_MODE
    global ROOT_PATH

    global firefox_ignored_sqlite_keys
    global safari_ignored_sqlite_keys
    global chrome_ignored_sqlite_keys
    firefox_ignored_sqlite_keys = {}
    safari_ignored_sqlite_keys = {}
    chrome_ignored_sqlite_keys = {}

    euid = os.geteuid()
    egid = os.getegid()

    parser = ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument(
        '-i', '--id', dest='incident_prefix', default='osxcollect',
        help='[OPTIONAL] An identifier which will be added as a prefix to the '
        'output file name.',
    )
    parser.add_argument(
        '-p', '--path', dest='rootpath', default='/',
        help='[OPTIONAL] Path to the OS X system to audit (e.g. /mnt/xxx). The'
        ' running system will be audited by default.',
    )
    parser.add_argument(
        '-s', '--section', dest='section_list', default=[], action='append',
        help='[OPTIONAL] Just run the named section.  May be specified more '
        'than once.',
    )
    parser.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help='[OPTIONAL] Enable verbose output and python breakpoints.',
    )
    parser.add_argument(
        '-c', '--collect-cookies', dest='collect_cookies_value',
        default=False, action='store_true',
        help='[OPTIONAL] Collect cookies\' value',
    )
    parser.add_argument(
        '-l', '--collect-local-storage',
        dest='collect_local_storage_value', default=False,
        action='store_true',
        help='[OPTIONAL] Collect the values stored in web browsers\' '
        'local storage',
    )
    args = parser.parse_args()

    DEBUG_MODE = args.debug
    ROOT_PATH = args.rootpath

    if ROOT_PATH == '/' and (euid != 0 and egid != 0):
        Logger.log_error('Must run as root!\n')
        return

    # Ignore cookies value
    if not args.collect_cookies_value:
        firefox_ignored_sqlite_keys['cookies'] = {'moz_cookies': ['value']}
        chrome_ignored_sqlite_keys['cookies'] = {'cookies': ['value']}

    # Ignore local storage value
    if not args.collect_local_storage_value:
        safari_ignored_sqlite_keys['localstorage'] = {'ItemTable': ['value']}
        chrome_ignored_sqlite_keys['local_storage'] = {'ItemTable': ['value']}

    # Create an incident ID
    prefix = args.incident_prefix
    incident_id = '{0}-{1}'.format(prefix, datetime.now().strftime('%Y_%m_%d-%H_%M_%S'))

    # Make a directory named for the output
    output_directory = './{0}'.format(incident_id)
    os.makedirs(output_directory)

    # Create an output file name
    output_file_name = pathjoin(output_directory, '{0}.json'.format(incident_id))

    # Collect information from plists and sqlite dbs and such
    with open(output_file_name, 'w') as output_file:
        Logger.set_output_file(output_file)
        with Logger.Extra('osxcollector_incident_id', incident_id):
            Collector().collect(section_list=args.section_list)

        # Archive log files
        log_file_archiver = LogFileArchiver()
        log_file_archiver.archive_logs(output_directory)
        log_file_archiver.compress_directory(incident_id, '.', output_directory)

        if not DEBUG_MODE:
            try:
                shutil.rmtree(output_directory)
            except Exception as e:
                Logger.log_exception(e)

    # Output message to the user
    sys.stderr.write('Wrote {0} lines.\nOutput in {1}.tar.gz\n'.format(Logger.lines_written, incident_id))


if __name__ == '__main__':
    main()
