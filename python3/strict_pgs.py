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
import string
import shutil

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
        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 7
                self.pw_name = fields[0]
                self.pw_passwd = fields[1]
                self.pw_uid = int(fields[2])
                self.pw_gid = int(fields[3])
                self.pw_gecos = fields[4]
                self.pw_dir = fields[5]
                self.pw_shell = fields[6]
            elif len(kargs) == 7:
                assert isinstance(kargs[2], int) and isinstance(kargs[3], int)
                self.pw_name = kargs[0]
                self.pw_passwd = kargs[1]
                self.pw_uid = kargs[2]
                self.pw_gid = kargs[3]
                self.pw_gecos = kargs[4]
                self.pw_dir = kargs[5]
                self.pw_shell = kargs[6]
            else:
                assert False

    class _GrpEntry:
        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 4
                self.gr_name = fields[0]
                self.gr_passwd = fields[1]
                self.gr_gid = int(fields[2])
                self.gr_mem = fields[3]
            elif len(kargs) == 4:
                assert isinstance(kargs[2], int)
                self.gr_name = kargs[0]
                self.gr_passwd = kargs[1]
                self.gr_gid = kargs[2]
                self.gr_mem = kargs[3]
            else:
                assert False

    class _ShadowEntry:
        def __init__(self, *kargs):
            if len(kargs) == 1:
                fields = kargs[0]
                assert len(fields) == 9
                self.sh_name = fields[0]
                self.sh_encpwd = fields[1]
            elif len(kargs) == 9:
                self.sh_name = kargs[0]
                self.sh_encpwd = kargs[1]
                assert kargs[2] == ""
                assert kargs[3] == ""
                assert kargs[4] == ""
                assert kargs[5] == ""
                assert kargs[6] == ""
                assert kargs[7] == ""
                assert kargs[8] == ""
            else:
                assert False

    _stdSystemUserList = ["root", "nobody"]
    _stdSystemGroupList = ["root", "nobody", "wheel", "users", "games"]

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
        self.pwdDict = dict()                    # key: username; value: _PwdEntry

        # filled by _parseGroup
        self.systemGroupList = []
        self.deviceGroupList = []
        self.perUserGroupList = []
        self.standAloneGroupList = []
        self.softwareGroupList = []
        self.deprecatedGroupList = []
        self.secondaryGroupsDict = dict()       # key: username; value: secondary group list of that user
        self.grpDict = dict()                    # key: groupname; value: _GrpEntry

        # filled by _parseShadow
        self.shadowEntryList = []
        self.shDict = dict()                    # key: username; value: _ShadowEntry

        # do parsing
        self._parsePasswd()
        self._parseGroup(self.normalUserList)
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

        # generate user id
        newUid = 1000
        while True:
            if newUid >= 10000:
                raise PgsAddUserError("Can not find a valid user id")
            if newUid in [v.pw_uid for v in self.pwdDict.values()]:
                newUid += 1
                continue
            if newUid in [v.gr_gid for v in self.grpDict.values()]:
                newUid += 1
                continue
            break

        # encrypt password
        newPwd = password

        # add user
        self.pwdDict[username] = self._PwdEntry(username, "x", newUid, newUid, "", "/home/%s" % (username), "/bin/bash")
        self.normalUserList.append(username)

        # add group
        self.grpDict[username] = self._GrpEntry(username, "x", newUid, "")
        self.perUserGroupList.append(username)

        # add shadow
        self.shDict[username] = self._ShadowEntry(username, newPwd, "", "", "", "", "", "", "")
        self.shadowEntryList.append(username)

    def removeNormalUser(self, username):
        """do nothing if the user doesn't exists"""

        self.shadowEntryList.remove(username)
        del self.shDict[username]

        del self.secondaryGroupsDict[username]
        for gname, entry in self.grpDict.items():
            ulist = entry.gr_mem.split(",")
            ulist.remove(username)
            self.grpDict[gname].gr_mem = ",".join(ulist)

        self.perUserGroupList.remove(username)
        del self.grpDict[username]

        self.normalUserList.remove(username)
        del self.pwdDict[username]

    def modifyNormalUser(self, username, opName, *kargs):
        assert False

    def addStandAloneGroup(self, groupname):
        assert groupname not in self.grpDict

        # generate group id
        newGid = 5000
        while True:
            if newGid >= 10000:
                raise PgsAddUserError("Can not find a valid group id")
            if newGid in [v.grp_gid for v in self.grpDict.values()]:
                newGid += 1
                continue
            break

        # add group
        self.grpDict[groupname] = self._GrpEntry(groupname, "x", newGid, "")
        self.standAloneGroupList.append(groupname)

    def removeStandAloneGroup(self, groupname):
        for glist in self.secondaryGroupsDict.values():
            glist.remove(groupname)
        self.standAloneGroupList.remove(groupname)
        del self.grpDict[groupname]

    def modifyStandAloneGroup(self, groupname, opName, *kargs):
        assert False

    def save(self):
        self._fixate()
        self._writePasswd()
        self._writeGroup()
        self._writeShadow()
        self._writeGroupShadow()

    def _parsePasswd(self):
        lineList = self._readFile(self.passwdFile).split("\n")

        needConvert = True
        for line in lineList:
            if line != "":
                if line == "# system users":
                    needConvert = False
                else:
                    needConvert = True
            break

        if not needConvert:
            part = ""
            for line in lineList:
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

                t = line.split(":")
                if len(t) != 7:
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
        else:
            for line in lineList:
                if line == "" or line.startswith("#"):
                    continue

                t = line.split(":")
                if len(t) != 7:
                    raise PgsFormatError("Invalid format of passwd file")

                self.pwdDict[t[0]] = self._PwdEntry(t)

                if t[0] in self._stdSystemUserList:
                    self.systemUserList.append(t[0])
                elif 1000 <= int(t[2]) < 10000:
                    self.normalUserList.append(t[0])
                else:
                    self.deprecatedUserList.append(t[0])

    def _parseGroup(self, normalUserList):
        lineList = self._readFile(self.groupFile).split("\n")

        needConvert = True
        for line in lineList:
            if line != "":
                if line == "# system groups":
                    needConvert = False
                else:
                    needConvert = True
            break

        if not needConvert:
            part = ""
            for line in lineList:
                if line == "":
                    continue

                if line == "# system groups":
                    part = "system"
                    continue
                elif line == "# per-user groups":
                    part = "per-user"
                    continue
                elif line == "# stand-alone groups":
                    part = "stand-alone"
                    continue
                elif line == "# device groups":
                    part = "device"
                    continue
                elif line == "# software groups":
                    part = "software"
                    continue
                elif line == "# deprecated":
                    part = "deprecated"
                    continue

                t = line.split(":")
                if len(t) != 4:
                    raise PgsFormatError("Invalid format of group file")

                self.grpDict[t[0]] = self._GrpEntry(t)

                if part == "system":
                    self.systemGroupList.append(t[0])
                elif part == "per-user":
                    self.perUserGroupList.append(t[0])
                elif part == "stand-alone":
                    self.standAloneGroupList.append(t[0])
                elif part == "device":
                    self.deviceGroupList.append(t[0])
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
        else:
            for line in lineList:
                if line == "" or line.startswith("#"):
                    continue

                t = line.split(":")
                if len(t) != 4:
                    raise PgsFormatError("Invalid format of group file")

                self.grpDict[t[0]] = self._GrpEntry(t)

                if t[0] in self._stdSystemGroupList:
                    self.systemGroupList.append(t[0])
                elif t[0] in normalUserList:
                    self.perUserGroupList.append(t[0])
                elif 1000 <= int(t[2]) < 10000:
                    self.standAloneGroupList.append(t[0])
                else:
                    self.deprecatedGroupList.append(t[0])

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
                raise PgsFormatError("Invalid format of shadow file")

            self.shDict[t[0]] = self._ShadowEntry(t)
            self.shadowEntryList.append(t[0])

    def _writePasswd(self):
        shutil.copy2(self.passwdFile, self.passwdFile + "-")
        with open(self.passwdFile, "w") as f:
            print("# system users", file=f)
            for uname in self.systemUserList:
                print(self._pwd2str(self.pwdDict[uname]), file=f)
            print("", file=f)

            print("# normal users", file=f)
            for uname in self.normalUserList:
                print(self._pwd2str(self.pwdDict[uname]), file=f)
            print("", file=f)

            print("# software users", file=f)
            for uname in self.softwareUserList:
                print(self._pwd2str(self.pwdDict[uname]), file=f)
            print("", file=f)

            print("# deprecated", file=f)
            for uname in self.deprecatedUserList:
                print(self._pwd2str(self.pwdDict[uname]), file=f)
            print("", file=f)

    def _writeGroup(self):
        shutil.copy2(self.groupFile, self.groupFile + "-")
        with open(self.groupFile, "w") as f:
            print("# system groups", file=f)
            for gname in self.systemGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

            print("# per-user groups", file=f)
            for gname in self.perUserGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

            print("# stand-alone groups", file=f)
            for gname in self.standAloneGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

            print("# device groups", file=f)
            for gname in self.deviceGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

            print("# software groups", file=f)
            for gname in self.softwareGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

            print("# deprecated", file=f)
            for gname in self.deprecatedGroupList:
                print(self._grp2str(self.grpDict[gname]), file=f)
            print("", file=f)

    def _writeShadow(self):
        shutil.copy2(self.shadowFile, self.shadowFile + "-")
        with open(self.shadowFile, "w") as f:
            for sname in self.shadowEntryList:
                print(self._sh2str(self.shDict[sname]), file=f)

    def _writeGroupShadow(self):
        shutil.copy2(self.gshadowFile, self.gshadowFile + "-")
        with open(self.gshadowFile, "w") as f:
            f.truncate()

    def _pwd2str(self, e):
        return "%s:%s:%d:%d:%s:%s:%s" % (e.pw_name, "x", e.pw_uid, e.pw_gid, e.pw_gecos, e.pw_dir, e.pw_shell)

    def _grp2str(self, e):
        return "%s:%s:%d:%s" % (e.gr_name, "x", e.gr_gid, e.gr_mem)

    def _sh2str(self, e):
        return "%s:%s:::::::" % (e.sh_name, e.sh_encpwd)

    def _verifyStage1(self):
        """passwd/group/shadow are not recoverable if stage1 verification fails"""

        # check system user list
        if set(self.systemUserList) != set(self._stdSystemUserList):
            raise PgsFormatError("Invalid system user list")
        for uname in self.systemUserList:
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for system user %s" % (uname))
            if uname not in self.shDict:
                raise PgsFormatError("No shadow entry for system user %s" % (uname))

        # check normal user list
        for uname in self.normalUserList:
            if not (1000 <= self.pwdDict[uname].pw_uid < 10000):
                raise PgsFormatError("User ID out of range for normal user %s" % (uname))
            if self.pwdDict[uname].pw_uid != self.grpDict[uname].gr_gid:
                raise PgsFormatError("User ID and group ID not equal for normal user %s" % (uname))
            if self.pwdDict[uname].pw_gecos != "":
                raise PgsFormatError("No comment is allowed for normal user %s" % (uname))
            if uname not in self.shDict:
                raise PgsFormatError("No shadow entry for normal user %s" % (uname))
            if len(self.shDict[uname].sh_encpwd) <= 4:
                raise PgsFormatError("No password for normal user %s" % (uname))

        # check system group list
        if self.systemGroupList != self._stdSystemGroupList:
            raise PgsFormatError("Invalid system group list")

        # check per-user group list
        if self.perUserGroupList != self.normalUserList:
            raise PgsFormatError("Invalid per-user group list")

        # check stand-alone group list
        for gname in self.standAloneGroupList:
            if not (1000 <= self.grpDict[gname].gr_gid < 10000):
                raise PgsFormatError("Group ID out of range for stand-alone group %s" % (gname))

    def _verifyStage2(self):
        """passwd/group/shadow are recoverable if stage2 verification fails"""

        # check system user list
        if self.systemUserList != self._stdSystemUserList:
            raise PgsFormatError("Invalid system user order")

        # check normal user list
        uidList = [self.pwdDict[x].pw_uid for x in self.normalUserList]
        if uidList != sorted(uidList):
            raise PgsFormatError("Invalid normal user order")

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
            if uname in self.shDict:
                raise PgsFormatError("Should not have shadow entry for software user %s" % (uname))

        # check stand-alone group list
        gidList = [self.grpDict[x].gr_gid for x in self.standAloneGroupList]
        if gidList != sorted(gidList):
            raise PgsFormatError("Invalid stand-alone group order")

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
        i = 0
        if self.systemUserList != self.shadowEntryList[i:len(self.systemUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.systemUserList)
        if self.normalUserList != self.shadowEntryList[i:len(self.normalUserList)]:
            raise PgsFormatError("Invalid shadow file entry order")
        i += len(self.normalUserList)
        if i != len(self.shadowEntryList):
            raise PgsFormatError("Redundant shadow file entries")

        # check /etc/gshadow
        if len(self._readFile(self.gshadowFile)) > 0:
            raise PgsFormatError("gshadow file should be empty")

    def _fixate(self):
        # sort system user list
        assert set(self.systemUserList) == set(self._stdSystemUserList)
        self.systemUserList = self._stdSystemUserList

        # sort normal user list
        self.normalUserList.sort(key=lambda x: self.pwdDict[x].pw_uid)

        # sort system group list
        assert set(self.systemGroupList) == set(self._stdSystemGroupList)
        self.systemGroupList = self._stdSystemGroupList

        # sort per-user group list
        assert set(self.perUserGroupList) == set(self.normalUserList)
        self.perUserGroupList = self.normalUserList

        # sort stand-alone group list
        self.standAloneGroupList.sort(key=lambda x: self.grpDict[x].pw_gid)

        # sort shadow entry list
        assert set(self.shadowEntryList) >= set(self.systemUserList + self.normalUserList)
        self.shadowEntryList = self.systemUserList + self.normalUserList

        # remove redundant shadow entries
        for uname in set(self.shDict.keys()) - set(self.shadowEntryList):
            del self.shDict[uname]

    def _readFile(self, filename):
        """Read file, returns the whole content"""

        with open(filename, 'r') as f:
            return f.read()

    def _writeFile(self, filename, buf):
        """Write buffer to file"""

        with open(filename, 'w') as f:
            f.write(buf)
