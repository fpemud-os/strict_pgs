#!/usr/bin/env python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import sys
import shutil
import unittest
if sys.version_info >= (3, 0):
	sys.path.insert(0, "../python3")
else:
	sys.path.insert(0, "../python2")
from strict_pgs import PasswdGroupShadow

class ReadEmptyData(unittest.TestCase):
	def runTest(self):
		pgs = PasswdGroupShadow("./empty-data")

class ReadFullData(unittest.TestCase):
	def runTest(self):
		pgs = PasswdGroupShadow("./full-data")

def suite():
	suite = unittest.TestSuite()
	suite.addTest(ReadEmptyData())
	suite.addTest(ReadFullData())
	return suite

if __name__ == "__main__":
	unittest.main(defaultTest = 'suite')
