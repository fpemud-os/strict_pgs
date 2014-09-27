#!/usr/bin/env python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import sys
import shutil
import unittest

curDir = os.path.dirname(os.path.abspath(__file__))
if sys.version_info >= (3, 0):
	sys.path.insert(0, os.path.join(curDir, "../python3"))
else:
	sys.path.insert(0, os.path.join(curDir, "../python2"))
from strict_pgs import PasswdGroupShadow

class ReadEmptyData(unittest.TestCase):
	def runTest(self):
		rootDir = os.path.join(curDir, "empty-data")
		pgs = PasswdGroupShadow(rootDir)

class ReadFullData(unittest.TestCase):
	def runTest(self):
		rootDir = os.path.join(curDir, "full-data")
		pgs = PasswdGroupShadow(rootDir)

def suite():
	suite = unittest.TestSuite()
	suite.addTest(ReadEmptyData())
	suite.addTest(ReadFullData())
	return suite

if __name__ == "__main__":
	unittest.main(defaultTest = 'suite')
