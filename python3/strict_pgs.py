#!/usr/bin/env python3

# strict_pgs.py - strict passwd/group/shadow
#
# Copyright (c) 2005-2011 Fpemud <fpemud@sina.com>
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

import os
from collections import OrderedDict

__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


class PgsFormatError(Exception):
    pass


class PgsAddUserError(Exception):
    pass


class PgsRemoveUserError(Exception):
    pass


class PasswdGroupShadow:
    """A passwd/group/shadow file with special format and rules"""

    class _PwdEntry:
        def __init__(self, fields):
            self.pw_name = fields[0]
            self.pw_passwd = fields[1]
            self.pw_uid = int(fields[2])
            self.pw_gid = int(fields[3])
            self.pw_gecos = fields[4]
            self.pw_dir = fields[5]
            self.pw_shell = fields[6]

    class _GrpEntry:
        def __init__(self, fields):
            self.gr_name = fields[0]
            self.gr_passwd = fields[1]
            self.gr_gid = int(fields[2])
            self.gr_mem = fields[3]

    class _ShadowEntry:
        def __init__(self, pwd):
            self.sh_pwd = pwd

    def __init__(self, dirPrefix="/"):
        self.dirPrefix = dirPrefix
        self.passwdFile = os.path.join(dirPrefix, "etc", "passwd")
        self.groupFile = os.path.join(dirPrefix, "etc", "group")
        self.shadowFile = os.path.join(dirPrefix, "etc", "shadow")
        self.gshadowFile = os.path.join(dirPrefix, "etc", "gshadow")

        # filled by _parsePasswd
        self.systemUserList = []
        self.normalUserList = []
        self.softwareUserList = []
        self.deprecatedUserList = []
        self.pwdDict = dict()

        # filled by _parseGroup
        self.systemGroupList = []
        self.deviceGroupList = []
        self.perUserGroupList = []
        self.standAloneGroupList = []
        self.softwareGroupList = []
        self.deprecatedGroupList = []
        self.secondaryGroupsDict = dict()        # key: username; value: secondary group list of that user
        self.grpDict = dict()

        # filled by _parseShadow
        self.shadowDict = OrderedDict()

        # do parsing
        self._parsePasswd()
        self._parseGroup()
        self._parseShadow()

        # do verify
        self._verifyStage1()

    def getSystemUserList(self):
        """returns system user name list"""
        return self.systemUserList

    def getNormalUserList(self):
        """returns normal user name list"""
        return self.normalUserList

    def getSystemGroupList(self):
        """returns system group name list"""
        return self.systemGroupList

    def getStandAloneGroupList(self):
        """returns stand-alone group name list"""
        return self.standAloneGroupList

    def getSecondaryGroupsOfUser(self, username):
        """returns group name list"""
        assert username in self.normalUserList
        return self.secondaryGroupsDict.get(username, [])

    def verify(self):
        """check passwd/group/shadow according to the critiera"""
        self._verifyStage1()
        self._verifyStage2()

    def addNormalUser(self, username, password):
        assert username not in self.pwdDict
        assert username not in self.grpDict

        # read files
        bufPasswd = self._readFile(self.passwdFile)
        bufGroup = self._readFile(self.groupFile)
        bufShadow = self._readFile(self.shadowFile)
        bufGshadow = self._readFile(self.gshadowFile)

        newUid = -1
        newGid = -1

        # modify bufPasswd
        if True:
            # get new user position
            lineList = bufPasswd.split("\n")
            parseState = 0
            lastLine = ""
            for i in range(0, len(lineList)):
                line = lineList[i]

                if line == "# Normal users":
                    parseState = 1
                    continue

                if parseState == 0:
                    continue

                if line.startswith("#"):
                    raise PgsAddUserError("Invalid format of passwd file")

                if line != "":
                    lastLine = line
                    continue

                if line == "":
                    break

            if parseState != 1:
                raise PgsAddUserError("Invalid format of passwd file")

            # get new user id
            newUid = 1000
            if lastLine != "":
                newUid = int(lastLine.split(":")[2]) + 1
            if newUid >= 10000:
                raise PgsAddUserError("Invalid new user id")

            # insert new user
            newUserLine = "%s:x:%d:%d::/home/%s:/bin/bash" % (username, newUid, newUid, username)
            lineList.insert(i, newUserLine)
            bufPasswd = "\n".join(lineList)

        # modify bufGroup
        if True:
            # get new group position
            lineList = bufGroup.split("\n")
            parseState = 0
            lastLine = ""
            for i in range(0, len(lineList)):
                line = lineList[i]

                if line == "# Normal groups":
                    parseState = 1
                    continue

                if parseState == 0:
                    continue

                if line.startswith("#"):
                    raise PgsAddUserError("Invalid format of group file")

                if line != "":
                    lastLine = line
                    continue

                if line == "":
                    break

            if parseState != 1:
                raise PgsAddUserError("Invalid format of group file")

            # get new group id
            newGid = 1000
            if lastLine != "":
                newGid = int(lastLine.split(":")[2]) + 1
            if newGid != newUid:
                raise PgsAddUserError("Invalid new group id")

            # insert new group
            newGroupLine = "%s:x:%d:" % (username, newGid)
            lineList.insert(i, newGroupLine)
            bufGroup = "\n".join(lineList)

        # modify bufShadow
        if True:
            if not bufShadow.endswith("\n"):
                bufShadow += "\n"
            bufShadow += "%s:x:15929:0:99999:7:::\n" % (username)

        # modify bufGshadow
        if True:
            if not bufGshadow.endswith("\n"):
                bufGshadow += "\n"
            bufGshadow += "%s:!::\n" % (username)

        # write files
        self._writeFile(self.passwdFile, bufPasswd)
        self._writeFile(self.groupFile, bufGroup)
        self._writeFile(self.shadowFile, bufShadow)
        self._writeFile(self.gshadowFile, bufGshadow)

    def removeNormalUser(self, username):
        """do nothing if the user doesn't exists
           can remove half-created user"""

        # read files
        bufPasswd = self._readFile(self.passwdFile)
        bufGroup = self._readFile(self.groupFile)
        bufShadow = self._readFile(self.shadowFile)
        bufGshadow = self._readFile(self.gshadowFile)

        # modify bufPasswd
        if True:
            lineList = bufPasswd.split("\n")
            parseState = 0
            for i in range(0, len(lineList)):
                line = lineList[i]
                if line == "# Normal users":
                    parseState = 1
                    continue
                if parseState == 0:
                    continue
                if line == "" or line.startswith("#"):
                    break
                if line.split(":")[0] == username:
                    parseState = 2
                    break
            if parseState == 0:
                raise PgsRemoveUserError("Invalid format of passwd file")
            if parseState == 2:
                lineList.pop(i)
                bufPasswd = "\n".join(lineList)

        # modify bufGroup
        if True:
            lineList = bufGroup.split("\n")
            parseState = 0
            for i in range(0, len(lineList)):
                line = lineList[i]
                if line == "# Normal groups":
                    parseState = 1
                    continue
                if parseState == 0:
                    continue
                if line == "" or line.startswith("#"):
                    break
                if line.split(":")[0] == username:
                    parseState = 2
                    break
            if parseState == 0:
                raise PgsRemoveUserError("Invalid format of group file")
            if parseState == 2:
                lineList.pop(i)
                bufGroup = "\n".join(lineList)

        # modify bufShadow
        if True:
            lineList = bufShadow.split("\n")
            found = False
            for i in range(0, len(lineList)):
                line = lineList[i]
                if line.split(":")[0] == username:
                    found = True
                    break
            if found:
                lineList.pop(i)
                bufShadow = "\n".join(lineList)

        # modify bufGshadow
        if True:
            lineList = bufGshadow.split("\n")
            found = False
            for i in range(0, len(lineList)):
                line = lineList[i]
                if line.split(":")[0] == username:
                    found = True
                    break
            if found:
                lineList.pop(i)
                bufGshadow = "\n".join(lineList)

        # write files
        self._writeFile(self.passwdFile, bufPasswd)
        self._writeFile(self.groupFile, bufGroup)
        self._writeFile(self.shadowFile, bufShadow)
        self._writeFile(self.gshadowFile, bufGshadow)

    def addStandAloneGroup(self, groupname):
        assert False

    def removeStandAloneGroup(self, groupname):
        assert False

    def save(self):
        assert False

    def _parsePasswd(self):
        part = ""
        for line in self._readFile(self.passwdFile).split("\n"):
            if line == "":
                continue

            if line == "# system users":
                part = "system"
                continue
            elif line == "# normal users":
                part = "normal"
                continue
            elif line == "# software users":
                part = "software"
                continue
            elif line == "# deprecated":
                part = "deprecated"
                continue

            if part == "":
                raise PgsFormatError("Invalid format of passwd file")

            t = line.split(":")
            if len(t) != 7:
                # passwd file entry format should be "username:passwod:uid:gid:comment:home-directory:shell"
                raise PgsFormatError("Invalid format of passwd file")

            self.pwdDict[t[0]] = self._PwdEntry(t)

            if part == "system":
                self.systemUserList.append(t[0])
            elif part == "normal":
                self.normalUserList.append(t[0])
            elif part == "software":
                self.softwareUserList.append(t[0])
            elif part == "deprecated":
                self.deprecatedUserList.append(t[0])
            else:
                assert False

    def _parseGroup(self):
        part = ""
        for line in self._readFile(self.groupFile).split("\n"):
            if line == "":
                continue

            if line == "# system groups":
                part = "system"
                continue
            elif line == "# device groups":
                part = "device"
                continue
            elif line == "# per-user groups":
                part = "per-user"
                continue
            elif line == "# stand-alone groups":
                part = "stand-alone"
                continue
            elif line == "# software groups":
                part = "software"
                continue
            elif line == "# deprecated":
                part = "deprecated"
                continue

            if part == "":
                raise PgsFormatError("Invalid format of group file")

            t = line.split(":")
            if len(t) != 4:
                # group file entry format should be "groupname:passwod:gid:member-list"
                raise PgsFormatError("Invalid format of group file")

            self.grpDict[t[0]] = self._GrpEntry(t)

            if part == "system":
                self.systemGroupList.append(t[0])
            elif part == "device":
                self.deviceGroupList.append(t[0])
            elif part == "per-user":
                self.perUserGroupList.append(t[0])
            elif part == "stand-alone":
                self.standAloneGroupList.append(t[0])
            elif part == "software":
                self.softwareGroupList.append(t[0])
            elif part == "deprecated":
                self.deprecatedGroupList.append(t[0])
            else:
                assert False

            for u in t[3].split(","):
                if u == "":
                    continue
                if u not in self.secondaryGroupsDict:
                    self.secondaryGroupsDict[u] = []
                self.secondaryGroupsDict[u].append(t[0])

    def _parseShadow(self):
        for line in self._readFile(self.shadowFile).split("\n"):
            if line == "":
                continue

            t = line.split(":")
            if len(t) != 9:
                # shadow file entry format should be "username:encrypted-password:last:min:max:warn:inactive:expire"
                # the last 6 fields are for password aging and account lockout features, they should be empty
                raise PgsFormatError("Invalid format of shadow file")

            self.shadowDict[t[0]] = self._ShadowEntry(t[1])

    def _verifyStage1(self):
        # check system user list
        if self.systemUserList != ["root", "nobody"]:
            raise PgsFormatError("Invalid system user list")
        for uname in self.systemUserList:
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for system user %s" % (uname))
            if uname not in self.shadowDict:
                raise PgsFormatError("No shadow entry for system user %s" % (uname))

        # check normal user list
        if self.normalUserList != self.perUserGroupList:
            raise PgsFormatError("Invalid normal user list")
        for uname in self.normalUserList:
            if not (1000 <= self.pwdDict[uname].pw_uid < 10000):
                raise PgsFormatError("User ID out of range for normal user %s" % (uname))
            if self.pwdDict[uname].pw_uid != self.grpDict[uname].gr_gid:
                raise PgsFormatError("User ID and group ID not equal for normal user %s" % (uname))
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for normal user %s" % (uname))
            if uname not in self.shadowDict:
                raise PgsFormatError("No shadow entry for normal user %s" % (uname))
            if len(self.shadowDict[uname].sh_pwd) <= 4:
                raise PgsFormatError("No password for normal user %s" % (uname))

        # check system group list
        if self.systemGroupList != ["root", "nobody", "wheel", "users", "games"]:
            raise PgsFormatError("Invalid system group list")

        # check per-user group list
        if self.perUserGroupList != self.normalUserList:
            raise PgsFormatError("Invalid per-user group list")

        # check stand-alone group list
        for gname in self.standAloneGroupList:
            if not (1000 <= self.grpDict[gname].gr_gid < 10000):
                raise PgsFormatError("Group ID out of range for stand-alone group %s" % (gname))

    def _verifyStage2(self):
        # check normal user list
        uidList = [self.pwdDict[x].pw_uid for x in self.normalUserList]
        if uidList != sorted(uidList):
            raise PgsFormatError("Invalid normal user sequence")

        # check software user list
        if self.softwareUserList != self.softwareGroupList:
            raise PgsFormatError("Invalid software user list")
        for uname in self.softwareUserList:
            if self.pwdDict[uname].pw_uid >= 1000:
                raise PgsFormatError("User ID out of range for software user %s" % (uname))
            if self.pwdDict[uname].pw_uid != self.grpDict[uname].gr_gid:
                raise PgsFormatError("User ID and group ID not equal for software user %s" % (uname))
            if self.pwdDict[uname].pw_shell != "/sbin/nologin":
                raise PgsFormatError("Invalid shell for software user %s" % (uname))
            if uname in self.shadowDict:
                raise PgsFormatError("Should not have shadow entry for software user %s" % (uname))

        # check stand-alone group list
        gidList = [self.grpDict[x].gr_gid for x in self.standAloneGroupList]
        if gidList != sorted(gidList):
            raise PgsFormatError("Invalid stand-alone group sequence")

        # check software group list
        for gname in self.softwareGroupList:
            if self.grpDict[gname].gr_gid >= 1000:
                raise PgsFormatError("Group ID out of range for software group %s" % (gname))

        # check secondary groups dict
        for uname, grpList in self.secondaryGroupsDict.items():
            if uname not in self.systemUserList + self.normalUserList + self.softwareUserList:
                continue
            for gname in grpList:
                if gname in self.deprecatedGroupList:
                    raise PgsFormatError("User %s is a member of deprecated group %s" % (uname, gname))

        # check /etc/shadow
        shadowEntryList = self.shadowDict.keys()
        i = 0
        if self.systemUserList != shadowEntryList[i:len(self.systemUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.systemUserList)
        if self.normalUserList != shadowEntryList[i:len(self.normalUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.systemUserList)
        if i != len(shadowEntryList):
            raise PgsFormatError("Redundant shadow file entries")

        # check /etc/gshadow
        if len(self._readFile(self.gshadowFile)) > 0:
            raise PgsFormatError("gshadow file should be empty")

    def _readFile(self, filename):
        """Read file, returns the whole content"""

        with open(filename, 'r') as f:
            return f.read()

    def _writeFile(self, filename, buf):
        """Write buffer to file"""

        with open(filename, 'w') as f:
            f.write(buf)
