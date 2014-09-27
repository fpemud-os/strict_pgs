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

class ReadDataEmpty(unittest.TestCase):
	def runTest(self):
		rootDir = os.path.join(curDir, "data-empty")
		pgs = PasswdGroupShadow(rootDir)

		self.assertEqual(pgs.getSystemUserList(), ["root", "nobody"])
		self.assertEqual(pgs.getNormalUserList(), [])
		self.assertEqual(pgs.getSystemGroupList(), ["root", "nobody", "wheel", "users", "games"])
		self.assertEqual(pgs.getStandAloneGroupList(), [])

class ReadDataFull(unittest.TestCase):
	def runTest(self):
		rootDir = os.path.join(curDir, "data-full")
		pgs = PasswdGroupShadow(rootDir)

		self.assertEqual(pgs.getSystemUserList(), ["root", "nobody"])
		self.assertEqual(pgs.getNormalUserList(), ["usera", "userb"])
		self.assertEqual(pgs.getSystemGroupList(), ["root", "nobody", "wheel", "users", "games"])
		self.assertEqual(pgs.getStandAloneGroupList(), ["groupa", "groupb", "groupc"])

		self.assertEqual(pgs.getSecondaryGroupsOfUser("usera"), ["groupa", "groupb", "groupc"])
		self.assertEqual(pgs.getSecondaryGroupsOfUser("userb"), [])

class ReadDataNeedConvert(unittest.TestCase):
	def runTest(self):
		rootDir = os.path.join(curDir, "data-need-convert")
		pgs = PasswdGroupShadow(rootDir)

		self.assertEqual(pgs.getSystemUserList(), ["root", "nobody"])
		self.assertEqual(pgs.getNormalUserList(), ["usera", "userb"])
		self.assertEqual(pgs.getSystemGroupList(), ["root", "nobody", "wheel", "users", "games"])
		self.assertEqual(pgs.getStandAloneGroupList(), [])

		self.assertEqual(pgs.getSecondaryGroupsOfUser("usera"), ["wheel", "games", "git", "cdrom"])
		self.assertEqual(pgs.getSecondaryGroupsOfUser("userb"), [])

class ConvertAndSave(unittest.TestCase):
	def runTest(self):
		srcDir = os.path.join(curDir, "data-need-convert")
		rootDir = os.path.join(curDir, "test")
		shutil.copytree(srcDir, rootDir)
		try:
			pgs = PasswdGroupShadow(rootDir)
			pgs.save()

			pgs2 = PasswdGroupShadow(rootDir)

			self.assertEqual(pgs2.getSystemUserList(), ["root", "nobody"])
			self.assertEqual(pgs2.getNormalUserList(), ["usera", "userb"])
			self.assertEqual(pgs2.getSystemGroupList(), ["root", "nobody", "wheel", "users", "games"])
			self.assertEqual(pgs2.getStandAloneGroupList(), [])

			self.assertEqual(pgs2.getSecondaryGroupsOfUser("usera"), ["wheel", "games", "git", "cdrom"])
			self.assertEqual(pgs2.getSecondaryGroupsOfUser("userb"), [])
		finally:
			shutil.rmtree(rootDir)

class AddOneNormalUser(unittest.TestCase):
	def setUp(self):
		srcDir = os.path.join(curDir, "data-empty")
		rootDir = os.path.join(curDir, "test")
		shutil.copytree(srcDir, rootDir)

	def tearDown(self):
		rootDir = os.path.join(curDir, "test")
#		shutil.rmtree(rootDir)

	def runTest(self):
		rootDir = os.path.join(curDir, "test")
		pgs = PasswdGroupShadow(rootDir)
		pgs.addNormalUser("userc")
		pgs.save()

		pgs2 = PasswdGroupShadow(rootDir)
		self.assertEqual(pgs.getNormalUserList(), ["usera", "userb", "userc"])

def suite():
	suite = unittest.TestSuite()
	suite.addTest(ReadDataEmpty())
	suite.addTest(ReadDataFull())
	suite.addTest(ReadDataNeedConvert())
	suite.addTest(ConvertAndSave())
#	suite.addTest(AddOneNormalUser())
	return suite

if __name__ == "__main__":
	unittest.main(defaultTest = 'suite')
