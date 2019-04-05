# -*- coding: utf-8 -*-
from setuptools import setup

from osxcollector import __version__


with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
    name='osxcollector',
    version=__version__,
    author='Yelp Security',
    author_email='opensource@yelp.com',
    description="A tool for answering \"How'd that malware get there?\"",
    long_description=long_description,
    long_description_content_type='text/markdown',
    license='GNU General Public License',
    url='https://github.com/Yelp/osxcollector',
    setup_requires='setuptools',
    packages=['osxcollector'],
    entry_points={
        'console_scripts': ['osxcollector=osxcollector.osxcollector:main'],
    },
)
