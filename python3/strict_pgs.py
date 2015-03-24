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
import re
import time
import fcntl
import errno
import shutil

__author__ = "fpemud@sina.com (Fpemud)"
__version__ = "0.0.1"


class PgsFormatError(Exception):
    pass


class PgsLockError(Exception):
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

    _manageFlag = "# manged by fpemud-usermanager"
    _stdSystemUserList = ["root", "nobody"]
    _stdDeprecatedUserList = ["bin", "daemon", "adm", "shutdown", "halt", "operator", "lp"]
    _stdSystemGroupList = ["root", "nobody", "wheel", "users", "games"]
    _stdDeviceGroupList = ["tty", "disk", "lp", "mem", "kmem", "floppy", "console", "audio", "cdrom", "tape", "video", "cdrw", "usb", "plugdev", "input"]
    _stdDeprecatedGroupList = ["bin", "daemon", "sys", "adm"]

    def __init__(self, dirPrefix="/", readOnly=True):
        self.valid = True
        self.dirPrefix = dirPrefix
        self.readOnly = readOnly

        self.loginDefFile = os.path.join(dirPrefix, "etc", "login.defs")
        self.passwdFile = os.path.join(dirPrefix, "etc", "passwd")
        self.groupFile = os.path.join(dirPrefix, "etc", "group")
        self.shadowFile = os.path.join(dirPrefix, "etc", "shadow")
        self.gshadowFile = os.path.join(dirPrefix, "etc", "gshadow")

        self.lockFile = os.path.join(dirPrefix, "etc", ".pwd.lock")
        self.lockFd = None

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

        # filled by _parseLoginDef
        self.uidMin = -1
        self.uidMax = -1
        self.gidMin = -1
        self.gidMax = -1

        # do parsing
        self._parseLoginDef()
        if not self.readOnly:
            self._lockPwd()
        try:
            self._parsePasswd()
            self._parseGroup(self.normalUserList)
            self._parseShadow()
        except:
            if not self.readOnly:
                self._unlockPwd()
            raise

        # do verify
        self._verifyStage1()

    def getSystemUserList(self):
        """returns system user name list"""
        assert self.valid
        return self.systemUserList

    def getNormalUserList(self):
        """returns normal user name list"""
        assert self.valid
        return self.normalUserList

    def getSystemGroupList(self):
        """returns system group name list"""
        assert self.valid
        return self.systemGroupList

    def getStandAloneGroupList(self):
        """returns stand-alone group name list"""
        assert self.valid
        return self.standAloneGroupList

    def getSecondaryGroupsOfUser(self, username):
        """returns group name list"""
        assert self.valid
        assert username in self.normalUserList
        return self.secondaryGroupsDict.get(username, [])

    def verify(self):
        """check passwd/group/shadow according to the critiera"""
        assert self.valid
        self._verifyStage1()
        self._verifyStage2()

    def addNormalUser(self, username, password):
        assert self.valid
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
        assert self.valid

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
        assert self.valid
        assert False

    def addStandAloneGroup(self, groupname):
        assert self.valid
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
        assert self.valid

        for glist in self.secondaryGroupsDict.values():
            glist.remove(groupname)
        self.standAloneGroupList.remove(groupname)
        del self.grpDict[groupname]

    def modifyStandAloneGroup(self, groupname, opName, *kargs):
        assert self.valid
        assert False

    def close(self):
        assert self.valid

        if not self.readOnly:
            self._fixate()
            self._writePasswd()
            self._writeGroup()
            self._writeShadow()
            self._writeGroupShadow()
            self._unlockPwd()
        self.valid = False

    def _parseLoginDef(self):
        if not os.path.exists(self.loginDefFile):
             raise PgsFormatError("%s is missing" % (self.loginDefFile))
        buf = self._readFile(self.loginDefFile)

        m = re.search("\\s*UID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
             self.uidMin = int(m.group(1))
        else:
             raise PgsFormatError("Invalid format of %s, UID_MIN is missing" % (self.loginDefFile))

        m = re.search("\\s*UID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
             self.uidMax = int(m.group(1))
        else:
             raise PgsFormatError("Invalid format of %s, UID_MAX is missing" % (self.loginDefFile))

        m = re.search("\\s*GID_MIN\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
             self.gidMin = int(m.group(1))
        else:
             raise PgsFormatError("Invalid format of %s, GID_MIN is missing" % (self.loginDefFile))

        m = re.search("\\s*GID_MAX\s+([0-9]+)\\s*$", buf, re.M)
        if m is not None:
             self.gidMax = int(m.group(1))
        else:
             raise PgsFormatError("Invalid format of %s, GID_MAX is missing" % (self.loginDefFile))

    def _parsePasswd(self):
        lineList = self._readFile(self.passwdFile).split("\n")
        for line in lineList:
            if line == "" or line.startswith("#"):
                continue

            t = line.split(":")
            if len(t) != 7:
                raise PgsFormatError("Invalid format of passwd file")

            self.pwdDict[t[0]] = self._PwdEntry(t)

            if t[0] in self._stdSystemUserList:
                self.systemUserList.append(t[0])
            elif self.uidMin <= int(t[2]) < self.uidMax:
                self.normalUserList.append(t[0])
            elif t[0] in self._stdDeprecatedUserList:
                self.deprecatedUserList.append(t[0])
            else:
                self.softwareUserList.append(t[0])

    def _parseGroup(self, normalUserList):
        lineList = self._readFile(self.groupFile).split("\n")
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
            elif t[0] in self._stdDeviceGroupList:
                self.deviceGroupList.append(t[0])
            elif t[0] in self._stdDeprecatedGroupList:
                self.deprecatedGroupList.append(t[0])
            elif self.gidMin <= int(t[2]) < self.gidMax:
                self.standAloneGroupList.append(t[0])
            else:
                self.softwareGroupList.append(t[0])

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
            f.write(self._manageFlag + "\n")

            for uname in self.systemUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.normalUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.softwareUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")
            f.write("\n")
            for uname in self.deprecatedUserList:
                f.write(self._pwd2str(self.pwdDict[uname]))
                f.write("\n")

    def _writeGroup(self):
        shutil.copy2(self.groupFile, self.groupFile + "-")
        with open(self.groupFile, "w") as f:
            f.write(self._manageFlag + "\n")

            for gname in self.systemGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.perUserGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.standAloneGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.deviceGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.softwareGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")
            f.write("\n")
            for gname in self.deprecatedGroupList:
                f.write(self._grp2str(self.grpDict[gname]))
                f.write("\n")

    def _writeShadow(self):
        shutil.copy2(self.shadowFile, self.shadowFile + "-")
        with open(self.shadowFile, "w") as f:
            for sname in self.shadowEntryList:
                f.write(self._sh2str(self.shDict[sname]))
                f.write("\n")

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
        """passwd/group/shadow are not fixable if stage1 verification fails"""

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
            if not (self.uidMin <= self.pwdDict[uname].pw_uid < self.uidMax):
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
            if not (self.gidMin <= self.grpDict[gname].gr_gid < self.gidMax):
                raise PgsFormatError("Group ID out of range for stand-alone group %s" % (gname))

    def _verifyStage2(self):
        """passwd/group/shadow are fixable if stage2 verification fails"""

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
            if self.pwdDict[uname].pw_uid >= self.uidMin:
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
            if self.grpDict[gname].gr_gid >= self.gidMin:
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

    def _lockPwd(self):
        """Use the same implementation as lckpwdf() in glibc"""

        assert self.lockFd is None
        self.lockFd = os.open(self.lockFile, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            t = time.clock()
            while time.clock() - t < 15.0:
                try:
                    fcntl.lockf(self.lockFd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except IOError as e:
                    if e.errno != errno.EACCESS and e.errno != errno.EAGAIN:
                        raise
                time.sleep(1.0)
            raise PgsLockError("Failed to acquire lock")
        except:
            os.close(self.lockFd)
            self.lockFd = None
            raise

    def _unlockPwd(self):
        """Use the same implementation as ulckpwdf() in glibc"""

        assert self.lockFd is not None
        os.close(self.lockFd)
        self.lockFd = None
