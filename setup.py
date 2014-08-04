# -*- coding: utf-8 -*-
from setuptools import setup

from osxcollector import __version__


setup(
    name="osxcollector",
    version=__version__,
    author="Jakub Sendor",
    author_email="jsendor@yelp.com",
    description="Gathers information from plists, sqlite DBs, and the local filesystem to get information for analyzing a malware infection.",
    packages=["osxcollector"],
)
