# -*- coding: utf-8 -*-
import logging

# Suppress output from tldextract module
logging.getLogger('tldextract').addHandler(logging.NullHandler())
