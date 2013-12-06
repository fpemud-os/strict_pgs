#!/usr/bin/env python

import os
import sys
import unittest

if sys.version_info >= (3, 0):
	sys.path.insert(0, "../python3")
else:
	sys.path.insert(0, "../python2")
from strict_pgs import PasswdGroupShadow

class MyTestCase(unittest.TestCase):
	def setUp(self):
		self.prefix = os.path.dirname(os.path.abspath(__file__))

	def tearDown(self):
		pass

	def runTest(self):
		pgs = PasswdGroupShadow(self.prefix)

def suite():
	suite = unittest.TestSuite()
	suite.addTest(MyTestCase())
	return suite

if __name__ == "__main__":
	unittest.main(defaultTest = 'suite')
