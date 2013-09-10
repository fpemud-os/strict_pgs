#!/usr/bin/env python

# import statements
import os
import sys
import distutils.extension
from distutils.util import get_platform
try:
    # First try to load most advanced setuptools setup.
    from setuptools import setup
except:
    # Fall back if setuptools is not installed.
    from distutils.core import setup

platform = get_platform()

# check Python's version
if sys.version_info < (2, 4):
    sys.stderr.write('This module requires at least Python 2.4\n')
    sys.exit(1)

# check linux platform
if not platform.startswith('linux'):
    sys.stderr.write("This module is not available on %s\n" % platform)
    sys.exit(1)


classif = [
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GPLv3 License',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.4',
    'Programming Language :: Python :: 2.5',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.0',
    'Programming Language :: Python :: 3.1',
    'Programming Language :: Python :: 3.2',
    'Topic :: Software Development :: Libraries :: Python Modules',
    ]


# Select branch
if sys.version_info >= (3, 0):
    package_dir = {'': 'python3'}
else:
    package_dir = {'': 'python2'}

# Do setup
setup(
    name='strict_pgs',
    version='0.0.1',
    description='Extracting passwd/group/shadow information',
    author='Fpemud',
    author_email='fpemud@sina.com',
    license='GPLv3 License',
    platforms='Linux',
    classifiers=classif,
    url='http://github.com/fpemud/strict_pgs',
    download_url='',
    py_modules=['strict_pgs'],
    package_dir=package_dir,
    )
