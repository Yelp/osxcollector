# -*- coding: utf-8 -*-
import re
from setuptools import setup


with open('README.md', 'r') as f:
    long_description = f.read()

with open('osxcollector/osxcollector.py', 'r') as f:
    # This is done to avoid loading the entire module which may cause import errors
    version_regex = re.compile(r'__version__\s*=\s*[\'"]([0-9\.]+)[\'"]')
    version_line = next(l for l in f if version_regex.search(l))
    __version__ = version_regex.search(version_line).group(1)

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
    install_requires=[
        'macholib>=1.7',
        'pyobjc>=3.0.4',
        'xattr>=0.8.0',
    ],
    entry_points={
        'console_scripts': ['osxcollector=osxcollector.osxcollector:main'],
    },
)
