# -*- coding: utf-8 -*-
from setuptools import setup

from osxcollector.osxcollector import __version__

setup(
    name="osxcollector",
    version=__version__,
    author="Yelp Security",
    author_email="opensource@yelp.com",
    description="A tool for answering \"How'd that malware get there?\"",
    packages=["osxcollector"],
    entry_points={
        'console_scripts': ['osxcollector=osxcollector.osxcollector:main']
    },
)
