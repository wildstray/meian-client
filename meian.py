#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Meain TCP protocol client
#
# Copyright (C) 2018, Andrea Tuccia
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import division, print_function, absolute_import
import asyncore
import binascii
from collections import OrderedDict as OD
import dicttoxml
import re
import socket
import time
import threading
import uuid
import xml.etree.ElementTree as ET
import xmltodict

class ConnectionError(Exception):
    pass

class PushClientError(Exception):
    pass

class LoginError(Exception):
    pass

class ResponseError(Exception):
    pass

class MeianClient():

    seq = 0
    timeout = 10

    def __init__(self, host, port, uid, pwd):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((host, port))
        except socket.timeout:
            self.sock.close()
            raise ConnectionError("Connection error")
        cmd = OD()
        cmd['Id'] = STR(uid)
        cmd['Pwd'] = PWD(pwd)
        cmd['Type'] = 'TYP,ANDROID|0'
        cmd['Token'] = STR(str(uuid.uuid4()))
        cmd['Action'] = 'TYP,IN|0'
        cmd['Err'] = None
        xpath = '/Root/Pair/Client'
        root = self._create(xpath, cmd)
        self.client = self._(xpath, cmd)
        if self.client['Err']:
            raise ClientError("Login error")

    def __del__(self):
        self.sock.close()

    def GetAlarmStatus(self):
        cmd = OD()
        cmd['DevStatus'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetAlarmStatus'
        return self._(xpath, cmd)

    def GetByWay(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetByWay'
        return self._(xpath, cmd, True)

    def GetDefense(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetDefense'
        return self._(xpath, cmd, True)

    def GetEmail(self):
        cmd = OD()
        cmd['Ip'] = None
        cmd['Port'] = None
        cmd['User'] = None
        cmd['Pwd'] = None
        cmd['EmailSend'] = None
        cmd['EmailRecv'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetEmail'
        return self._(xpath, cmd)

    def GetEvents(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetEvents'
        return self._(xpath, cmd, True)

    def GetGprs(self):
        cmd = OD()
        cmd['Apn'] = None
        cmd['User'] = None
        cmd['Pwd'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetGprs'
        return self._(xpath, cmd)

    def GetLog(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetLog'
        return self._(xpath, cmd, True)

    def GetNet(self):
        cmd = OD()
        cmd['Mac'] = None
        cmd['Name'] = None
        cmd['Ip'] = None
        cmd['Gate'] = None
        cmd['Subnet'] = None
        cmd['Dns1'] = None
        cmd['Dns2'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetNet'
        return self._(xpath, cmd)

    def GetOverlapZone(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetOverlapZone'
        return self._(xpath, cmd, True)

    def GetPairServ(self):
        cmd = OD()
        cmd['Ip'] = None
        cmd['Port'] = None
        cmd['Id'] = None
        cmd['Pwd'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetPairServ'
        return self._(xpath, cmd)

    def GetPhone(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['RepeatCnt'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetPhone'
        return self._(xpath, cmd, True)

    def GetRemote(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetRemote'
        return self._(xpath, cmd, True)

    def GetRfid(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetRfid'
        return self._(xpath, cmd, True)

    def GetRfidType(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetRfidType'
        return self._(xpath, cmd, True)

    def GetSendby(self, cid):
        cmd = OD()
        cmd['Cid'] = STR(cid)
        cmd['Tel'] = None
        cmd['Voice'] = None
        cmd['Sms'] = None
        cmd['Email'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetSendby'
        return self._(xpath, cmd)

    def GetSensor(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetSensor'
        return self._(xpath, cmd, True)

    def GetServ(self):
        cmd = OD()
        cmd['En'] = None
        cmd['Ip'] = None
        cmd['Port'] = None
        cmd['Name'] = None
        cmd['Pwd'] = None
        cmd['Cnt'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetServ'
        return self._(xpath, cmd)

    def GetSwitch(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetSwitch'
        return self._(xpath, cmd, True)

    def GetSwitchInfo(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetSwitchInfo'
        return self._(xpath, cmd, True)

    def GetSys(self):
        cmd = OD()
        cmd['InDelay'] = None
        cmd['OutDelay'] = None
        cmd['AlarmTime'] = None
        cmd['WlLoss'] = None
        cmd['AcLoss'] = None
        cmd['ComLoss'] = None
        cmd['ArmVoice'] = None
        cmd['ArmReport'] = None
        cmd['ForceArm'] = None
        cmd['DoorCheck'] = None
        cmd['BreakCheck'] = None
        cmd['AlarmLimit'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetSys'
        return self._(xpath, cmd)

    def GetTel(self):
        cmd = OD()
        cmd['En'] = None
        cmd['Code'] = None
        cmd['Cnt'] = None
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetTel'
        return self._(xpath, cmd, True)

    def GetTime(self):
        cmd = OD()
        cmd['En'] = None
        cmd['Name'] = None
        cmd['Type'] = None
        cmd['Time'] = None
        cmd['Dst'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetTime'
        return self._(xpath, cmd)

    def GetVoiceType(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetVoiceType'
        return self._(xpath, cmd, True)

    def GetZone(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetZone'
        return self._(xpath, cmd, True)

    def GetZoneType(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetZoneType'
        return self._(xpath, cmd, True)

    def WlsStudy(self):
        cmd = OD()
        cmd['Err'] = None
        xpath = '/Root/Host/WlsStudy'
        return self._(xpath, cmd)

    def ConfigWlWaring(self):
        cmd = OD()
        cmd['Err'] = None
        xpath = '/Root/Host/ConfigWlWaring'
        return self._(xpath, cmd)

    def FskStudy(self, en):
        cmd = OD()
        cmd['Study'] = BOL(en)
        cmd['Err'] = None
        xpath = '/Root/Host/FskStudy'
        return self._(xpath, cmd)

    def GetWlsStatus(self, num):
        cmd = OD()
        cmd['Num'] = S32(num)
        cmd['Bat'] = None
        cmd['Tamp'] = None
        cmd['Status'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetWlsStatus'
        return self._(xpath, cmd)

    def DelWlsDev(self, num):
        cmd = OD()
        cmd['Num'] = S32(num)
        cmd['Err'] = None
        xpath = '/Root/Host/DelWlsDev'
        return self._(xpath, cmd)

    def WlsSave(self, typ, num, code):
        cmd = OD()
        cmd['Type'] = 'TYP,NO|%d' % typ
        cmd['Num'] = S32(num, 1)
        cmd['Code'] = STR(code)
        cmd['Err'] = None
        xpath = '/Root/Host/WlsSave'
        return self._(xpath, cmd)

    def GetWlsList(self):
        cmd = OD()
        cmd['Total'] = None
        cmd['Offset'] = S32(0)
        cmd['Ln'] = None
        cmd['Err'] = None
        xpath = '/Root/Host/GetWlsList'
        return self._(xpath, cmd)

    def SwScan(self):
        cmd = OD()
        cmd['Err'] = None
        xpath = '/Root/Host/SwScan'
        return self._(xpath, cmd)

    def Reset(self, ret):
        cmd = OD()
        cmd['Ret'] = BOL(ret)
        cmd['Err'] = None
        xpath = '/Root/Host/Reset'
        return self._(xpath, cmd)

    def OpSwitch(self, pos, en):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['En'] = BOL(en)
        cmd['Err'] = None
        xpath = '/Root/Host/OpSwitch'
        return self._(xpath, cmd)

    def SetAlarmStatus(self, status):
        cmd = OD()
        cmd['DevStatus'] = TYP(status, ['ARM', 'DISARM', 'STAY', 'CLEAR'])
        cmd['Err'] = None
        xpath = '/Root/Host/SetAlarmStatus'
        return self._(xpath, cmd)

    def SetByWay(self, pos, en):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['En'] = BOL(en)
        cmd['Err'] = None
        xpath = '/Root/Host/SetByWay'
        return self._(xpath, cmd)

    def SetDefense(self, pos, hmdef = '00:00', hmundef = '00:00'):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Def'] = STR(hmdef)
        cmd['Undef'] = STR(hmundef)
        cmd['Err'] = None
        xpath = '/Root/Host/SetDefense'
        return self._(xpath, cmd)

    def SetEmail(self, ip, port, user, pwd, emailsend, emailrecv):
        cmd = OD()
        cmd['Ip'] = STR(ip)
        cmd['Port'] = S32(port)
        cmd['User'] = STR(user)
        cmd['Pwd'] = PWD(pwd)
        cmd['EmailSend'] = STR(emailsend)
        cmd['EmailRecv'] = STR(emailrecv)
        cmd['Err'] = None
        xpath = '/Root/Host/SetEmail'
        return self._(xpath, cmd)

    def SetGprs(self, apn, user, pwd):
        cmd = OD()
        cmd['Apn'] = STR(apn)
        cmd['User'] = STR(user)
        cmd['Pwd'] = PWD(pwd)
        cmd['Err'] = None
        xpath = '/Root/Host/SetGprs'
        return self._(xpath, cmd)

    def SetNet(self, mac, name, ip, gate, subnet, dns1, dns2):
        cmd = OD()
        cmd['Mac'] = MAC(mac)
        cmd['Name'] = STR(name)
        cmd['Ip'] = IPA(ip)
        cmd['Gate'] = IPA(gate)
        cmd['Subnet'] = IPA(subnet)
        cmd['Dns1'] = IPA(dns1)
        cmd['Dns2'] = IPA(dns2)
        cmd['Err'] = None
        xpath = '/Root/Host/SetNet'
        return self._(xpath, cmd)

    def SetOverlapZone(self, pos, zone1, zone2, time):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Zone1'] = S32(pos, 1)
        cmd['Zone1'] = S32(pos, 1)
        cmd['Time'] = S32(pos, 1)
        cmd['Err'] = None
        xpath = '/Root/Host/SetOverlapZone'
        return self._(xpath, cmd)

    def SetPairServ(self, ip, port, uid, pwd):
        cmd = OD()
        cmd['Ip'] = IPA(ip)
        cmd['Port'] = S32(port, 1)
        cmd['Id'] = STR(uid)
        cmd['Pwd'] = PWD(pwd)
        cmd['Err'] = None
        xpath = '/Root/Host/SetPairServ'
        return self._(xpath, cmd)

    def SetPhone(self, pos, num):
        cmd = OD()
        cmd['Type'] = TYP(1, ['F', 'L'])
        cmd['Pos'] = S32(pos, 1)
        cmd['Num'] = STR(num)
        cmd['Err'] = None
        xpath = '/Root/Host/SetPhone'
        return self._(xpath, cmd)

    def SetRfid(self, pos, code, typ, msg):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Type'] = S32(typ, ['NO', 'DS', 'HS', 'DM' 'HM', 'DC'])
        cmd['Code'] = STR(code)
        cmd['Msg'] = STR(msg)
        cmd['Err'] = None
        xpath = '/Root/Host/SetRfid'
        return self._(xpath, cmd)

    def SetRemote(self, pos, code):
        cmd = OD()#
        cmd['Pos'] = S32(pos, 1)
        cmd['Code'] = STR(code)
        cmd['Err'] = None
        xpath = '/Root/Host/SetRemote'
        return self._(xpath, cmd)

    def SetSendby(self, cid, tel, voice, sms, email):
        cmd = OD()
        cmd['Cid'] = STR(cid)
        cmd['Tel'] = BOL(tel)
        cmd['Voice'] = BOL(voice)
        cmd['Sms'] = BOL(sms)
        cmd['Email'] = BOL(email)
        cmd['Err'] = None
        xpath = '/Root/Host/SetSendby'
        return self._(xpath, cmd)

    def SetSensor(self, pos, code):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Code'] = STR(code)
        cmd['Err'] = None
        xpath = '/Root/Host/SetSensor'
        return self._(xpath, cmd)

    def SetServ(self, en, ip, port, name, pwd, cnt):
        cmd = OD()
        cmd['En'] = BOL(en)
        cmd['Ip'] = STR(ip)
        cmd['Port'] = S32(port, 1)
        cmd['Name'] = STR(name)
        cmd['Pwd'] = PWD(pwd)
        cmd['Cnt'] = S32(cnt, 1)
        cmd['Err'] = None
        xpath = '/Root/Host/SetServ'
        return self._(xpath, cmd)

    def SetSwitch(self, pos, code):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Code'] = STR(code)
        cmd['Err'] = None
        xpath = '/Root/Host/SetSwitch'
        return self._(xpath, cmd)

    def SetSwitchInfo(self, pos, name, hmopen = '00:00', hmclose = '00:00'):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Name'] = STR(name[:7].encode('hex'))
        cmd['Open'] = STR(hmopen)
        cmd['Close'] = STR(hmclose)
        cmd['Err'] = None
        xpath = '/Root/Host/SetSwitchInfo'
        return self._(xpath, cmd)

    def SetSys(self, indelay, outdelay, alarmtime, wlloss, acloss, comeloss, armvoice, armreport, forcearm, doorcheck, breakcheck, alarmlimit):
        cmd = OD()
        cmd['InDelay'] = S32(indelay, 1)
        cmd['OutDelay'] = S32(outdelay, 1)
        cmd['AlarmTime'] = S32(alarmtime, 1)
        cmd['WlLoss'] = S32(wlloss, 1)
        cmd['AcLoss'] = S32(acloss, 1)
        cmd['ComLoss'] = S32(comloss, 1)
        cmd['ArmVoice'] = BOL(armvoice)
        cmd['ArmReport'] = BOL(armreport)
        cmd['ForceArm'] = BOL(forcearm)
        cmd['DoorCheck'] = BOL(doorcheck)
        cmd['BreakCheck'] = BOL(breakcheck)
        cmd['AlarmLimit'] = BOL(alarmlimit)
        cmd['Err'] = None
        xpath = '/Root/Host/SetSys'
        return self._(xpath, cmd)

    def SetTel(self, en, code, cnt):
        cmd = OD()
        cmd['Typ'] = TYP(0, ['F', 'L'])
        cmd['En'] = BOL(en)
        cmd['Code'] = NUM(code)
        cmd['Cnt'] = S32(cnt, 1)
        cmd['Err'] = None
        xpath = '/Root/Host/SetTel'
        return self._(xpath, cmd)

    def SetTime(self, en, name, typ, time, dst):
        cmd = OD()
        cmd['En'] = BOL(en)
        cmd['Name'] = STR(name)
        cmd['Type'] = 'TYP,0|%d' % typ
        cmd['Time'] = DTA(time)
        cmd['Dst'] = BOL(dst)
        cmd['Err'] = None
        xpath = '/Root/Host/SetTime'
        return self._(xpath, cmd)

    def SetZone(self, pos, typ, zone, name):
        cmd = OD()
        cmd['Pos'] = S32(pos, 1)
        cmd['Type'] = TYP(typ)
        cmd['Zone'] = TYP(zone)
        cmd['Name'] = STR(name)
        cmd['Err'] = None
        xpath = '/Root/Host/SetZone'
        return self._(xpath, cmd)

    def _(self, xpath, cmd, is_list = False, offset = 0, l = None):
        if offset > 0:
            cmd['Offset'] = S32(offset)
        root = self._create(xpath, cmd)
        self._send(root)
        resp = self._receive()
        if is_list == False:
            return self._select(resp, xpath)
        if l is None:
            l = []
        total = self._select(resp, '%s/Total' % xpath)
        ln = self._select(resp, '%s/Ln' % xpath)
        for i in xrange(0, ln):
            event = self._select(resp, '%s/L%d' % (xpath, i))
            l.append(self._select(resp, '%s/L%d' % (xpath, i)))
        offset += ln
        if total > offset:
            self._(xpath, cmd, is_list, offset, l)
        return l

    def _send(self, root):
        xml = dicttoxml.dicttoxml(root, attr_type=False, root=False)
        self.seq += 1
        mesg = "@ieM%04d%04d0000%s%04d" % (len(xml), self.seq, self._xor(xml), self.seq)
        self.sock.send(mesg)

    def _receive(self):
        try:
            data = self.sock.recv(1024)
        except socket.timeout:
            self.sock.close()
            raise ConnectionError("Connection error")
        return xmltodict.parse(self._xor(data[16:-4]), xml_attribs=False, dict_constructor=dict, postprocessor=self._xmlread)

    def _xor(self, input):
        sz = bytearray.fromhex('0c384e4e62382d620e384e4e44382d300f382b382b0c5a6234384e304e4c372b10535a0c20432d171142444e58422c421157322a204036172056446262382b5f0c384e4e62382d620e385858082e232c0f382b382b0c5a62343830304e2e362b10545a0c3e432e1711384e625824371c1157324220402c17204c444e624c2e12')
        buf = bytearray(input)
        for i in xrange(len(input)):
            ki = i & 0x7f
            buf[i] = buf[i] ^ sz[ki]
        return str(buf)

    def _create(self, path, mydict = {}):
        root = {}
        elem = root
        try:
            plist = path.strip('/').split('/')
            k = len(plist) - 1
            for i, j in enumerate(plist):
                elem[j] = {}
                if i == k:
                    elem[j] = mydict
                elem = elem.get(j)
        except:
            pass
        return root

    def _select(self, mydict, path):
        elem = mydict
        try:
            for i in path.strip('/').split('/'):
                try:
                    i = int(i)
                    elem = elem[i]
                except ValueError:
                    elem = elem.get(i)
        except:
            pass
        return elem

    def _xmlread(self, path, key, value):
        try:
            input = value
            BOL = re.compile('BOL\|([FT])')
            DTA = re.compile('DTA(,\d+)*\|(\d{4}\.\d{2}.\d{2}.\d{2}.\d{2}.\d{2})')
            ERR = re.compile('ERR\|(\d{2})')
            HMA = re.compile('HMA,(\d+)\|(\d{2}:\d{2})')
            IPA = re.compile('IPA,(\d+)\|(([0-2]?\d{0,2}\.){3}([0-2]?\d{0,2}))')
            MAC = re.compile('MAC,(\d+)\|(([0-9A-F]{2}[:-]){5}([0-9A-F]{2}))')
            NEA = re.compile('NEA,(\d+)\|([0-9A-F]+)')
            NUM = re.compile('NUM,(\d+),(\d+)\|(\d*)')
            PWD = re.compile('PWD,(\d+)\|(.*)')
            S32 = re.compile('S32,(\d+),(\d+)\|(\d*)')
            STR = re.compile('STR,(\d+)\|(.*)')
            TYP = re.compile('TYP,(\w+)\|(\d+)')
            if BOL.match(input):
                bol = BOL.search(input).groups()[0]
                if bol == "T":
                    value = True
                if bol == "F":
                    value =  False
            elif DTA.match(input):
                dta = DTA.search(input).groups()[1]
                value =  time.strptime(dta,'%Y.%m.%d.%H.%M.%S')
            elif ERR.match(input):
                value =  int(ERR.search(input).groups()[0])
            elif HMA.match(input):
                hma = HMA.search(input).groups()[1]
                value =  time.strptime(hma,'%H:%M')
            elif IPA.match(input):
                value =  str(IPA.search(input).groups()[1])
            elif MAC.match(input):
                value =  str(MAC.search(input).groups()[1])
            elif NEA.match(input):
                value =  str(NEA.search(input).groups()[1])
            elif NUM.match(input):
                value =  str(NUM.search(input).groups()[2])
            elif PWD.match(input):
                value =  str(PWD.search(input).groups()[1])
            elif S32.match(input):
                value =  int(S32.search(input).groups()[2])
            elif STR.match(input):
                value =  str(STR.search(input).groups()[1])
            elif TYP.match(input):
                value =  int(TYP.search(input).groups()[1])
            else:
                raise ResponseError('Unknown data type %s' % input)
            return key, value
        except (ValueError, TypeError):
            return key, value

class MeianPushClient(asyncore.dispatcher, threading.Thread, MeianClient):

    daemon = True
    keepalive = 60
    timeout = 10

    def __init__(self, host, port, uid, handler):
        if not callable(handler):
            raise AttributeError('handler is not a function')
        self.host = host
        self.port = port
        self.handler = handler
        cmd = OD()
        cmd['Id'] = STR(uid)
        cmd['Err'] = None
        xpath = '/Root/Pair/Push'
        self.mesg = self._create(xpath, cmd)
        threading.Thread.__init__(self)
        self._thread_sockets = dict()
        asyncore.dispatcher.__init__(self, map=self._thread_sockets)
        self.start()

    def __del__(self):
        try:
            self.close()
        except AttributeError:
            pass
        else:
            self.close()

    def readable(self):
        return True

    def writable(self):
        if self.mesg is not None:
            return True
        return False

    def handle_connect(self):
        threading.Timer(self.keepalive, self._keepalive).start()
        pass

    def handle_error(self):
        self.close()
        raise

    def handle_read(self):
        data = self.recv(1024)
        head = data[0:4]

        if head == '%maI':
            threading.Timer(self.keepalive, self._keepalive).start()

        elif head == '@ieM':
            xpath = '/Root/Pair/Push'
            resp = xmltodict.parse(self._xor(data[16:-4]), xml_attribs=False, dict_constructor=dict, postprocessor=self._xmlread)
            self.push = self._select(resp, xpath)
            err = self._select(resp, '%s/Err' % xpath)
            if err:
                self.close()
                raise PushClientError("Push subscription error")

        elif head == '@alA':
            xpath = '/Root/Host/Alarm'
            resp = xmltodict.parse(self._xor(data[16:-4]), xml_attribs=False, dict_constructor=dict, postprocessor=self._xmlread)
            self.handler(self._select(resp, xpath))

        else:
            raise ResponseError("Response error")

    def handle_write(self):
        if self.mesg is not None:
            xml = dicttoxml.dicttoxml(self.mesg, attr_type=False, root=False)
            lenght = len(xml)
            mesg = "@ieM%04d%04d0000%s%04d" % (lenght, 0, self._xor(xml), 0)
            self.send(mesg)
            self.mesg = None

    def handle_close(self):
        self.close()

    def _keepalive(self):
        mesg = "%maI"
        self.send(mesg)
        self.mesg = None

    def run(self):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.connect((self.host, self.port))
        except socket.timeout:
            self.close()
            raise ConnectionError("Connection error")
        try:
            asyncore.loop(timeout=self.timeout, map = self._thread_sockets)
        except socket.error:
            self.close()
            raise ConnectionError("Connection error")

def BOL(en):
    if en == True:
        return 'BOL|T'
    else:
        return 'BOL|F'

def DTA(t):
    dta = time.strftime('%Y.%m.%d.%H.%M.%S', t)
    return 'DTA,%d|%s' % (len(dta), dta)

def PWD(text):
    return 'PWD,%d|%s' % (len(text), text)

def S32(val, pos = 0):
    return 'S32,%d,%d|%d' % (pos, pos, val)

def MAC(mac):
    return 'MAC,%d|%d' % (len(mac), mac)

def IPA(ip):
    return 'IPA,%d|%d' % (len(ip), ip)

def STR(text):
    text = str(text)
    return 'STR,%d|%s' % (len(text), text)

def TYP(val, typ = []):
    try:
        return 'TYP,%s|%d' % (typ[val], val)
    except IndexError:
        return 'TYP,NONE,|%d' % val

Cid = { '1100': 'Personal ambulance',
        '1101': 'Emergency',
        '1110': 'Fire',
        '1120': 'Emergency',
        '1131': 'Perimeter',
        '1132': 'Burglary',
        '1133': '24 hour',
        '1134': 'Delay',
        '1137': 'Dismantled',
        '1301': 'System AC fault',
        '1302': 'System battery failure',
        '1306': 'Programming changes',
        '1350': 'Communication failure',
        '1351': 'Telephone line fault',
        '1370': 'Circuit fault',
        '1381': 'Detector lost',
        '1384': 'Low battery detector',
        '1401': 'Disarm report',
        '1406': 'Alarm canceled',
        '1455': 'Automatic arming failed',
        '1570': 'Bypass Report',
        '1601': 'Manual communication test reports',
        '1602': 'Communications test reports',
        '3301': 'System AC recovery',
        '3302': 'System battery recovery',
        '3350': 'Communication resumes',
        '3351': 'Telephone line to restore',
        '3370': 'Loop recovery',
        '3381': 'Detector loss recovery',
        '3384': 'Detector low voltage recovery',
        '3401': 'Arming Report',
        '3441': 'Staying Report',
        '3570': 'Bypass recovery',
    }

TZ = {  0: 'GMT-12:00',
        1: 'GMT-11:00',
        2: 'GMT-10:00',
        3: 'GMT-09:00',
        4: 'GMT-08:00',
        5: 'GMT-07:00',
        6: 'GMT-06:00',
        7: 'GMT-05:00',
        8: 'GMT-04:00',
        9: 'GMT-03:30',
       10: 'GMT-03:00',
       11: 'GMT-02:00',
       12: 'GMT-01:00',
       13: 'GMT',
       14: 'GMT+01:00',
       15: 'GMT+02:00',
       16: 'GMT+03:00',
       17: 'GMT+04:00',
       18: 'GMT+05:00',
       19: 'GMT+05:30',
       20: 'GMT+05:45',
       21: 'GMT+06:00',
       22: 'GMT+06:30',
       23: 'GMT+07:00',
       24: 'GMT+08:00',
       25: 'GMT+09:00',
       26: 'GMT+09:30',
       27: 'GMT+10:00',
       28: 'GMT+11:00',
       29: 'GMT+12:00',
       30: 'GMT+13:00',
}


def main():
    host = '52.28.104.204'
    uid = '0449F7C65A'
    pwd = '1234'
    port = 18034
    myalarm = MeianClient(host, port, uid, pwd)
    print (myalarm.client)
    print (myalarm.GetAlarmStatus())
#    print (myalarm.WlsStudy())
#    print (myalarm.ConfigWlWaring())
#    print (myalarm.FskStudy(True))
#    print (myalarm.GetWlsStatus(0))
    print (myalarm.GetWlsList())
#    print (myalarm.SwScan())
    #print (myalarm.SetAlarmStatus(0))
    #print (myalarm.GetAlarmStatus())
    #print (myalarm.GetSwitch())
    #print (myalarm.SetSwitchInfo(0, 'Switch0', '01:23', '12:34'))
    #print (myalarm.GetSwitchInfo())
    #print (myalarm.OpSwitch(0, False))
    #print (myalarm.GetByWay())
    print (myalarm.GetDefense())
    #print (myalarm.GetEmail())
    #print (myalarm.GetEvents())
    #print (myalarm.GetGprs(1100))
    #print (myalarm.GetLog())
    #print (myalarm.GetNet())
    #print (myalarm.GetOverlapZone())
    #print (myalarm.GetPairServ())
    #print (myalarm.GetPhone())
    print (myalarm.GetRemote())
    #print (myalarm.GetRfid())
    #print (myalarm.GetRfidType())
    #print (myalarm.GetSendby(1100))
    print (myalarm.GetSensor())
    #print (myalarm.GetServ())
    #print (myalarm.GetSwitch())
    #print (myalarm.GetSwitchInfo())
    #print (myalarm.GetSys())
    #print (myalarm.GetTel())
    #print (myalarm.GetTime())
    #print (myalarm.GetVoiceType())
    #print (myalarm.GetZone())
    #print (myalarm.GetZoneType())

    def mytest(alarm):
        print (alarm)

#    mypush = MeianPushClient(host, port, uid, mytest)
#    while True:
#        time.sleep(60)
#    mypush.close()

if __name__ == "__main__":
    # execute only if run as a script
    main()
