# -*- coding: utf-8 -*-
#
# Config is a very simplistic class for reading YAML config.
#
import os

import yaml
from osxcollector.osxcollector import DictUtils


def config_get_deep(key, default=None):
    """Reads from the config.

    Args:
        key: Dictionary key to lookup in config
        default: Value to return if key is not found
    Returns:
        Value for config or default if not found otherwise
    """
    return DictUtils.get_deep(_read_config(), key, default)


def _read_config():
    """Reads and parses the YAML file.

    Returns:
        dict of config
    """
    for loc in os.curdir, os.path.expanduser('~'), os.environ.get('OSXCOLLECTOR_CONF', ''):
        try:
            with open(os.path.join(loc, 'osxcollector.yaml')) as source:
                return yaml.load(source.read())
        except IOError:
            pass
    return {}
