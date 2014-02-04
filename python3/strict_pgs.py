#!/usr/bin/env python

# strict_pgs.py - strict passwd group shadow
# Copyright (c) 2005-2011 Fpemu <fpemud@sina.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
strict_pgs

@author: Fpemud
@license: GPLv3 License
@contact: fpemud@sina.com
"""


__author__ = "fpemud@sina.com (Fpemud)"

__version__ = "0.0.1"

import os
import pwd
import grp

class PgsFormatError(Exception):
	pass

class PasswdGroupShadow:
	"""A passwd/group/shadow file with special format and rules"""

	class _ShadowEntry:
		def __init__(self, pwd):
			self.sh_pwd = pwd

	def __init__(self, dirPrefix):
		self.dirPrefix = dirPrefix
		self.passwdFile = os.path.join(dirPrefix, "etc", "passwd")
		self.groupFile = os.path.join(dirPrefix, "etc", "group")
		self.shadowFile = os.path.join(dirPrefix, "etc", "shadow")
		self.gshadowFile = os.path.join(dirPrefix, "etc", "gshadow")

		# filled by _parsePasswd
		self.systemUserList = []
		self.groupForSystemUserList = []
		self.normalUserList = []
		self.groupForNormalUserList = []
		self.softwareUserList = []
		self.groupForSoftwareUserList = []

		# filled by _parseGroup
		self.systemGroupList = []
		self.deviceGroupList = []
		self.normalGroupList = []
		self.softwareGroupList = []
		self.secondaryGroupsDict = dict()		# key: username; value: all secondary groups of that user

		# filled by _parseShadow
		self.shadowDict = dict()

		# do parsing
		self._parse()

	def getSystemUserList(self):
		return self.systemUserList

	def getNormalUserList(self):
		return self.normalUserList

	def getSecondaryGroupsOfUser(self, username):
		if username in self.secondaryGroupsDict:
			return self.secondaryGroupsDict[username]
		else:
			return []

	def _parse(self):
		# parse
		self._parsePasswd()
		self._parseGroup()
		self._parseShadow()

		# check system user list
		if self.systemUserList != [ "root", "nobody" ]:
			raise PgsFormatError("Invalid system user list")
		for uname in self.systemUserList:
			if uname not in self.shadowDict:
				raise PgsFormatError("No shadow entry for system user %s"%(uname))

		# check normal user list
		if self.normalUserList != self.groupForNormalUserList:
			raise PgsFormatError("Invalid normal user list")
		for uname in self.normalUserList:
			if pwd.getpwnam(uname).pw_uid not in range(1000, 10000):
				raise PgsFormatError("User ID out of range for normal user %s"%(uname))
			if pwd.getpwnam(uname).pw_uid != grp.getgrnam(uname).gr_gid:
				raise PgsFormatError("User ID and group ID not equal for normal user %s"%(uname))
			if uname not in self.shadowDict:
				raise PgsFormatError("No shadow entry for normal user %s"%(uname))
			if len(self.shadowDict[uname].sh_pwd) <= 4:
				raise PgsFormatError("No password for normal user %s"%(uname))

		# check software user list
		if self.softwareUserList != self.groupForSoftwareUserList:
			raise PgsFormatError("Invalid software user list")
		for uname in self.softwareUserList:
			if pwd.getpwnam(uname).pw_uid >= 1000:
				raise PgsFormatError("User ID out of range for software user %s"%(uname))
			if pwd.getpwnam(uname).pw_uid != grp.getgrnam(uname).gr_gid:
				raise PgsFormatError("User ID and group ID not equal for software user %s"%(uname))
			if pwd.getpwnam(uname).pw_shell != "/sbin/nologin":
				raise PgsFormatError("Invalid shell for software user %s"%(uname))
			if uname in self.shadowDict:
				raise PgsFormatError("Should not have shadow entry for software user %s"%(uname))

		# check system group list
		if self.systemGroupList != [ "root", "nogroup", "wheel", "users", "games" ]:
			raise PgsFormatError("Invalid system group list")

		# check normal group list
		if self.normalGroupList[len(self.normalGroupList) - len(self.groupForNormalUserList):] != self.groupForNormalUserList:
			raise PgsFormatError("Invalid normal group list")
		for gname in self.normalGroupList:
			if grp.getgrnam(gname).gr_gid not in range(1000, 10000):
				raise PgsFormatError("Group ID out of range for normal group %s"%(gname))

		# check software group list
		for gname in self.softwareGroupList:
			if grp.getgrnam(gname).gr_gid >= 1000:
				raise PgsFormatError("Group ID out of range for software group %s"%(gname))

	def _parsePasswd(self):
		lineList = self._readFile(self.passwdFile).split("\n")

		part = ""
		for line in lineList:
			if line == "":
				continue

			if line == "# System users":
				part = "system"
				continue
			elif line == "# Normal users":
				part = "normal"
				continue
			elif line == "# Software users":
				part = "software"
				continue
			elif line == "# Deprecated":
				part = "deprecated"
				continue

			if part == "":
				raise PgsFormatError("Invalid format of passwd file")

			t = line.split(":")
			if len(t) != 7:
				raise PgsFormatError("Invalid format of passwd file")

			if part == "system":
				self.systemUserList.append(t[0])
				self.groupForSystemUserList.append(grp.getgrgid(t[3]).gr_name)
			if part == "normal":
				self.normalUserList.append(t[0])
				self.groupForNormalUserList.append(grp.getgrgid(t[3]).gr_name)
			if part == "software":
				self.softwareUserList.append(t[0])
				self.groupForSoftwareUserList.append(grp.getgrgid(t[3]).gr_name)

	def _parseGroup(self):
		lineList = self._readFile(self.groupFile).split("\n")

		part = ""
		for line in lineList:
			if line == "":
				continue

			if line == "# System groups":
				part = "system"
				continue
			elif line == "# Device groups":
				part = "device"
				continue
			elif line == "# Normal groups":
				part = "normal"
				continue
			elif line == "# Software groups":
				part = "software"
				continue
			elif line == "# Deprecated":
				part = "deprecated"
				continue

			if part == "":
				raise PgsFormatError("Invalid format of group file")

			t = line.split(":")
			if len(t) != 4:
				raise PgsFormatError("Invalid format of group file")

			if part == "system":
				self.systemGroupList.append(t[0])
			if part == "device":
				self.deviceGroupList.append(t[0])
			if part == "normal":
				self.normalGroupList.append(t[0])
			if part == "software":
				self.softwareGroupList.append(t[0])

			for u in t[3].split(","):
				if u == "":
					continue
				if u not in self.secondaryGroupsDict:
					self.secondaryGroupsDict[u] = []
				self.secondaryGroupsDict[u].append(t[0])

	def _parseShadow(self):
		lineList = self._readFile(self.shadowFile).split("\n")

		for line in lineList:
			if line == "":
				continue

			t = line.split(":")
			if len(t) != 9:
				raise PgsFormatError("Invalid format of shadow file")

			self.shadowDict[t[0]] = self._ShadowEntry(t[1])

	def _readFile(self, filename):
		"""Read file, returns the whold content"""

		f = open(filename, 'r')
		buf = f.read()
		f.close()
		return buf

