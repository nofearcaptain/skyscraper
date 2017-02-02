#!/usr/bin/env python3

from Crypto.Cipher import AES
from hashlib import md5
from .toys import Figurine

# Dump formats
EML=0
BIN=1

class Dump():
    _s = [ 21371102791018180662551883353252,
           10203334846682372732060167677388,
           33413772399007802573272784412064,
           36904386810063333747133812619392 ]
    encrypted=None
    decrypted=None
    size=0
    _encmap=[]
    
    def __init__(self, dump, fmt=EML, encrypted=True):
        if fmt==EML:
            dump=[bytearray(bytes.fromhex(x.strip())) for x in dump.splitlines()]
        elif fmt==BIN:
            dump=[bytearray(dump[16*x:16*(x+1)]) for x in range(len(dump)//16)]
        self.size=len(dump)
        self._m=md5(dump[0]+dump[1])
        self._encmap=[not (n%4 == 3 or n < 8 or dump[n] == bytes(16)) for n in range(self.size)]
        if encrypted:
            self.encrypted=dump
            self.decrypted=[self.decryptn(n) for n in range(self.size)]
        else:
            self.decrypted=dump
            self.encrypted=[self.encryptn(n) for n in range(self.size)]

    def _getkey(self, n):
        m=self._m.copy()
        m.update(bytes([n, 32]))
        for i in self._s:
             m.update(bytes.fromhex("%x" % (i//4)))
        return m.digest()

    def encryptn(self, n, force=False, refresh=False):
        assert self.decrypted is not None
        if refresh:
            self._encmap=[not (n%4 == 3 or n < 8 or self.decrypted[n] == bytes(16)) for n in range(self.size)]
        if self._encmap[n] or force:
            if force:
                self._encmap[n] = True
            aes=AES.new(self._getkey(n), AES.MODE_ECB)
            return bytearray(aes.encrypt(bytes(self.decrypted[n])))
        else:
            return self.decrypted[n]

    def decryptn(self, n, force=False):
        assert self.encrypted is not None
        if self._encmap[n] or force:
            aes=AES.new(self._getkey(n), AES.MODE_ECB)
            return bytearray(aes.decrypt(bytes(self.encrypted[n])))
        else:
            return self.encrypted[n]

    def __repr__(self):
        return '\n'.join(['0x%02X %s %s %s' % (
                n,
                x.hex().upper(),
                '*' if z else ' ',
                y.hex().upper())
            for n,x,y,z in zip(
                range(self.size),
                self.decrypted,
                self.encrypted,
                self._encmap)])

    def getbin(self, encrypted=True):
        if encrypted:
            return b''.join(self.encrypted)
        else:
            return b''.join(self.decrypted)

    def geteml(self, encrypted=True):
        if encrypted:
            return '\n'.join([x.hex().upper() for x in self.encrypted])
        else:
            return '\n'.join([x.hex().upper() for x in self.decrypted])

    def _getchecksum(self, chksumtype, dataarea=0):
        if chksumtype == 0:
            return self.decrypted[0x01][0xE:0x10]
        headblock=[0x08, 0x24][dataarea]
        if chksumtype == 1:
            return self.decrypted[headblock][0xE:0x10]
        if chksumtype == 2:
            return self.decrypted[headblock][0xC:0xE]
        if chksumtype == 3:
            return self.decrypted[headblock][0xA:0xC]

    def _calcchecksum(self, chksumtype, dataarea=0):
        if chksumtype == 0:
            data = self.decrypted[0x00]+self.decrypted[0x01][:0xE]
        headblock=[0x08, 0x24][dataarea]
        if chksumtype == 1:
            data = self.decrypted[headblock][:0xE]
            if data == bytes(len(data)):
                return bytes(2)
            data+=(5).to_bytes(2, 'little')
        if chksumtype == 2:
            data = self.decrypted[headblock+1]+self.decrypted[headblock+2]+self.decrypted[headblock+4]
            if data == bytes(len(data)):
                return bytes(2)
        if chksumtype == 3:
            data = self.decrypted[headblock+5]+self.decrypted[headblock+6]+self.decrypted[headblock+8]+bytes(0xE0)
            if data == bytes(len(data)):
                return bytes(2)
        return crc16(data)

    def _setchecksum(self, chksumtype, dataarea=0):
        if chksumtype == 0:
            self.decrypted[0x01][0xE:] = self._calcchecksum(0)
        headblock=[0x08, 0x24][dataarea]
        if chksumtype == 1:
            self.decrypted[headblock][0xE:] = self._calcchecksum(1, dataarea)
        if chksumtype == 2:
            self.decrypted[headblock][0xC:0xE] = self._calcchecksum(2, dataarea)
        if chksumtype == 3:
            self.decrypted[headblock][0xA:0xC] = self._calcchecksum(3, dataarea)

    def validate(self, ignorecrc=False, ignoreuid=False, ignorekeys=False):
        if not ignorecrc:
            getcrc, calccrc = self._getchecksum(0).hex(), self._calcchecksum(0).hex()
            print('crc 0       : %s = %s -- %s' % (getcrc, calccrc,'ok' if getcrc==calccrc else 'FAIL'))
            for i in range(1,4):
                for j in range(2):
                    getcrc, calccrc = self._getchecksum(i,j).hex(), self._calcchecksum(i,j).hex()
                    print('crc %i area %i: %s = %s -- %s' % (i,j,getcrc, calccrc, 'ok' if getcrc==calccrc else 'FAIL'))
        if not ignoreuid:
            uid=self.getuid()
            getcc, calccc=self.decrypted[0][4:5].hex(), bytes([uid[0] ^ uid[1] ^ uid[2] ^ uid[3]]).hex()
            print('UID: %s cc: %s = %s -- %s' % (uid.hex().upper(), getcc, calccc, 'ok' if getcc==calccc else 'FAIL'))
        if not ignorekeys:
            keys=getmfkeys(self.getuid())
            for i,j in zip(range(3,4*16,4), range(16)):
                getkey, calckey = self.decrypted[i][:6].hex(), keys[j].hex()
                print('Sector 0x%02X keyA: %s = %s -- %s' % (j, getkey, calckey, 'ok' if getkey==calckey else 'FAIL'))
                getacl = self.decrypted[i][6:10].hex()
                calcacl = '0f0f0f69' if i==3 else '7f0f0869'
                print('Sector 0x%02X ACL:  %s = %s -- %s' % (j, getacl, calcacl, 'ok' if getacl==calcacl else 'FAIL'))
        # TODO: who knows one day we'll be able to check the ECC signature...

    # functions affecting the tag content:
    def refreshenc(self, force=False):
        self.encrypted=[self.encryptn(n, refresh=force) for n in range(self.size)]

    def refreshkeys(self):
        keys=getmfkeys(self.getuid())
        self._setchecksum(0)
        for i,j in zip(range(3,4*16,4), range(16)):
            self.decrypted[i][:6] = keys[j]

    def refreshcrc(self):
        self._setchecksum(0)
        for i in range(2):
            self._setchecksum(2,i)
        for i in range(2):
            self._setchecksum(3,i)
        # crc1 needs to be last as it covers crc2 & crc3
        for i in range(2):
            self._setchecksum(1,i)
        self.encrypted=[self.encryptn(n) for n in range(self.size)]

    def refresh(self):
        self.refreshacl()
        self.refreshkeys()
        self.refreshcrc()
        self.refreshenc(force=True)

    def reinit(self, hard=False):
        if hard:
            if self.getsubtype()[1] & 0xF0 >= 0x50:
                print("WARNING: since 2016, read-only data is signed.\nThis will very probably fail!\nTry without 'hard'")
            # wipe ECC? areas
            for n in 2, 4, 34, 62:
                self.decrypted[n]=bytearray(16)
            # wipe manufacturer area
                self.decrypted[0][8:] = bytearray(8)
            # wipe trading card ID
                self.decrypted[1][4:10] = bytearray(6)
            # wipe sector0 keyB
                self.decrypted[3][10:]=bytearray(6)
        for n in range(self.size):
            if n%4 != 3 and n > 4 and n not in [34, 62]:
                self.decrypted[n]=bytearray(16)
        self.refresh()

    def refreshacl(self):
        # tried other ACL but apparently we need this setup
        self.decrypted[3][6:10]=bytes.fromhex('0F0F0F69')
        for i in range(7,4*16,4):
            self.decrypted[i][6:10]=bytes.fromhex('7F0F0869')

    # setters & getters
    def gettoytype(self):
        return self.decrypted[1][0:2]
    def settoytype(self, value):
        value = bytes.fromhex(value) if type(value) is str else value
        value = value.to_bytes(4, 'big') if type(value) is int else value
        self.decrypted[1][0:2] = value
    def getsubtype(self):
        return self.decrypted[1][12:14]
    def setsubtype(self, value):
        value = bytes.fromhex(value) if type(value) is str else value
        value = value.to_bytes(4, 'big') if type(value) is int else value
        self.decrypted[1][12:14] = value
    def getuid(self):
        return self.decrypted[0][:4]
    def setuid(self, value=None):
        if self.getsubtype()[1] & 0xF0 >= 0x50:
            print("WARNING: since 2016, read-only data is signed.\nThis will very probably fail!")
        if value is None:
            # Random FNUID: UID0=xF
            import random
            value = random.getrandbits(32) | 0x0f000000
        value = bytes.fromhex(value) if type(value) is str else value
        value = value.to_bytes(4, 'big') if type(value) is int else value
        bcc=value[0] ^ value[1] ^ value[2] ^ value[3]
        self.decrypted[0][:4] = value
        self.decrypted[0][4] =  bcc
        self._setchecksum(0)
        self.refreshkeys()
        self.refreshenc()

crc64_table = [
    0x0000000000000000, 0x42F0E1EBA9EA3693, 0x85E1C3D753D46D26, 0xC711223CFA3E5BB5,
    0x493366450E42ECDF, 0x0BC387AEA7A8DA4C, 0xCCD2A5925D9681F9, 0x8E224479F47CB76A,
    0x9266CC8A1C85D9BE, 0xD0962D61B56FEF2D, 0x17870F5D4F51B498, 0x5577EEB6E6BB820B,
    0xDB55AACF12C73561, 0x99A54B24BB2D03F2, 0x5EB4691841135847, 0x1C4488F3E8F96ED4,
    0x663D78FF90E185EF, 0x24CD9914390BB37C, 0xE3DCBB28C335E8C9, 0xA12C5AC36ADFDE5A,
    0x2F0E1EBA9EA36930, 0x6DFEFF5137495FA3, 0xAAEFDD6DCD770416, 0xE81F3C86649D3285,
    0xF45BB4758C645C51, 0xB6AB559E258E6AC2, 0x71BA77A2DFB03177, 0x334A9649765A07E4,
    0xBD68D2308226B08E, 0xFF9833DB2BCC861D, 0x388911E7D1F2DDA8, 0x7A79F00C7818EB3B,
    0xCC7AF1FF21C30BDE, 0x8E8A101488293D4D, 0x499B3228721766F8, 0x0B6BD3C3DBFD506B,
    0x854997BA2F81E701, 0xC7B97651866BD192, 0x00A8546D7C558A27, 0x4258B586D5BFBCB4,
    0x5E1C3D753D46D260, 0x1CECDC9E94ACE4F3, 0xDBFDFEA26E92BF46, 0x990D1F49C77889D5,
    0x172F5B3033043EBF, 0x55DFBADB9AEE082C, 0x92CE98E760D05399, 0xD03E790CC93A650A,
    0xAA478900B1228E31, 0xE8B768EB18C8B8A2, 0x2FA64AD7E2F6E317, 0x6D56AB3C4B1CD584,
    0xE374EF45BF6062EE, 0xA1840EAE168A547D, 0x66952C92ECB40FC8, 0x2465CD79455E395B,
    0x3821458AADA7578F, 0x7AD1A461044D611C, 0xBDC0865DFE733AA9, 0xFF3067B657990C3A,
    0x711223CFA3E5BB50, 0x33E2C2240A0F8DC3, 0xF4F3E018F031D676, 0xB60301F359DBE0E5,
    0xDA050215EA6C212F, 0x98F5E3FE438617BC, 0x5FE4C1C2B9B84C09, 0x1D14202910527A9A,
    0x93366450E42ECDF0, 0xD1C685BB4DC4FB63, 0x16D7A787B7FAA0D6, 0x5427466C1E109645,
    0x4863CE9FF6E9F891, 0x0A932F745F03CE02, 0xCD820D48A53D95B7, 0x8F72ECA30CD7A324,
    0x0150A8DAF8AB144E, 0x43A04931514122DD, 0x84B16B0DAB7F7968, 0xC6418AE602954FFB,
    0xBC387AEA7A8DA4C0, 0xFEC89B01D3679253, 0x39D9B93D2959C9E6, 0x7B2958D680B3FF75,
    0xF50B1CAF74CF481F, 0xB7FBFD44DD257E8C, 0x70EADF78271B2539, 0x321A3E938EF113AA,
    0x2E5EB66066087D7E, 0x6CAE578BCFE24BED, 0xABBF75B735DC1058, 0xE94F945C9C3626CB,
    0x676DD025684A91A1, 0x259D31CEC1A0A732, 0xE28C13F23B9EFC87, 0xA07CF2199274CA14,
    0x167FF3EACBAF2AF1, 0x548F120162451C62, 0x939E303D987B47D7, 0xD16ED1D631917144,
    0x5F4C95AFC5EDC62E, 0x1DBC74446C07F0BD, 0xDAAD56789639AB08, 0x985DB7933FD39D9B,
    0x84193F60D72AF34F, 0xC6E9DE8B7EC0C5DC, 0x01F8FCB784FE9E69, 0x43081D5C2D14A8FA,
    0xCD2A5925D9681F90, 0x8FDAB8CE70822903, 0x48CB9AF28ABC72B6, 0x0A3B7B1923564425,
    0x70428B155B4EAF1E, 0x32B26AFEF2A4998D, 0xF5A348C2089AC238, 0xB753A929A170F4AB,
    0x3971ED50550C43C1, 0x7B810CBBFCE67552, 0xBC902E8706D82EE7, 0xFE60CF6CAF321874,
    0xE224479F47CB76A0, 0xA0D4A674EE214033, 0x67C58448141F1B86, 0x253565A3BDF52D15,
    0xAB1721DA49899A7F, 0xE9E7C031E063ACEC, 0x2EF6E20D1A5DF759, 0x6C0603E6B3B7C1CA,
    0xF6FAE5C07D3274CD, 0xB40A042BD4D8425E, 0x731B26172EE619EB, 0x31EBC7FC870C2F78,
    0xBFC9838573709812, 0xFD39626EDA9AAE81, 0x3A28405220A4F534, 0x78D8A1B9894EC3A7,
    0x649C294A61B7AD73, 0x266CC8A1C85D9BE0, 0xE17DEA9D3263C055, 0xA38D0B769B89F6C6,
    0x2DAF4F0F6FF541AC, 0x6F5FAEE4C61F773F, 0xA84E8CD83C212C8A, 0xEABE6D3395CB1A19,
    0x90C79D3FEDD3F122, 0xD2377CD44439C7B1, 0x15265EE8BE079C04, 0x57D6BF0317EDAA97,
    0xD9F4FB7AE3911DFD, 0x9B041A914A7B2B6E, 0x5C1538ADB04570DB, 0x1EE5D94619AF4648,
    0x02A151B5F156289C, 0x4051B05E58BC1E0F, 0x87409262A28245BA, 0xC5B073890B687329,
    0x4B9237F0FF14C443, 0x0962D61B56FEF2D0, 0xCE73F427ACC0A965, 0x8C8315CC052A9FF6,
    0x3A80143F5CF17F13, 0x7870F5D4F51B4980, 0xBF61D7E80F251235, 0xFD913603A6CF24A6,
    0x73B3727A52B393CC, 0x31439391FB59A55F, 0xF652B1AD0167FEEA, 0xB4A25046A88DC879,
    0xA8E6D8B54074A6AD, 0xEA16395EE99E903E, 0x2D071B6213A0CB8B, 0x6FF7FA89BA4AFD18,
    0xE1D5BEF04E364A72, 0xA3255F1BE7DC7CE1, 0x64347D271DE22754, 0x26C49CCCB40811C7,
    0x5CBD6CC0CC10FAFC, 0x1E4D8D2B65FACC6F, 0xD95CAF179FC497DA, 0x9BAC4EFC362EA149,
    0x158E0A85C2521623, 0x577EEB6E6BB820B0, 0x906FC95291867B05, 0xD29F28B9386C4D96,
    0xCEDBA04AD0952342, 0x8C2B41A1797F15D1, 0x4B3A639D83414E64, 0x09CA82762AAB78F7,
    0x87E8C60FDED7CF9D, 0xC51827E4773DF90E, 0x020905D88D03A2BB, 0x40F9E43324E99428,
    0x2CFFE7D5975E55E2, 0x6E0F063E3EB46371, 0xA91E2402C48A38C4, 0xEBEEC5E96D600E57,
    0x65CC8190991CB93D, 0x273C607B30F68FAE, 0xE02D4247CAC8D41B, 0xA2DDA3AC6322E288,
    0xBE992B5F8BDB8C5C, 0xFC69CAB42231BACF, 0x3B78E888D80FE17A, 0x7988096371E5D7E9,
    0xF7AA4D1A85996083, 0xB55AACF12C735610, 0x724B8ECDD64D0DA5, 0x30BB6F267FA73B36,
    0x4AC29F2A07BFD00D, 0x08327EC1AE55E69E, 0xCF235CFD546BBD2B, 0x8DD3BD16FD818BB8,
    0x03F1F96F09FD3CD2, 0x41011884A0170A41, 0x86103AB85A2951F4, 0xC4E0DB53F3C36767,
    0xD8A453A01B3A09B3, 0x9A54B24BB2D03F20, 0x5D45907748EE6495, 0x1FB5719CE1045206,
    0x919735E51578E56C, 0xD367D40EBC92D3FF, 0x1476F63246AC884A, 0x568617D9EF46BED9,
    0xE085162AB69D5E3C, 0xA275F7C11F7768AF, 0x6564D5FDE549331A, 0x279434164CA30589,
    0xA9B6706FB8DFB2E3, 0xEB46918411358470, 0x2C57B3B8EB0BDFC5, 0x6EA7525342E1E956,
    0x72E3DAA0AA188782, 0x30133B4B03F2B111, 0xF7021977F9CCEAA4, 0xB5F2F89C5026DC37,
    0x3BD0BCE5A45A6B5D, 0x79205D0E0DB05DCE, 0xBE317F32F78E067B, 0xFCC19ED95E6430E8,
    0x86B86ED5267CDBD3, 0xC4488F3E8F96ED40, 0x0359AD0275A8B6F5, 0x41A94CE9DC428066,
    0xCF8B0890283E370C, 0x8D7BE97B81D4019F, 0x4A6ACB477BEA5A2A, 0x089A2AACD2006CB9,
    0x14DEA25F3AF9026D, 0x562E43B4931334FE, 0x913F6188692D6F4B, 0xD3CF8063C0C759D8,
    0x5DEDC41A34BBEEB2, 0x1F1D25F19D51D821, 0xD80C07CD676F8394, 0x9AFCE626CE85B507 
] 

def crc64(bytesbuffer):
    # ECMA
    crc = 0
    for byte in bytesbuffer:
        tableIndex = ((crc >> 56) ^ byte) & 0xff
        crc = crc64_table[tableIndex] ^ (crc << 8) & 0xffffffffffffffff
    return crc

def crc16(bytesbuffer):
    # ccitt
    msb, lsb = 0xff, 0xff
    for byte in bytesbuffer:
        x = byte ^ msb
        x ^= (x >> 4)
        msb = (lsb ^ (x >> 3) ^ (x << 4)) & 255
        lsb = (x ^ (x << 5)) & 255
    return bytes([lsb, msb])


perm = [[0x0, 0x1, 0x3, 0x2, 0x7, 0x6, 0x4, 0x5, 0xF, 0xE, 0xC, 0xD, 0x8, 0x9, 0xB, 0xA],
        [0x1, 0x0, 0x2, 0x3, 0x6, 0x7, 0x5, 0x4, 0xE, 0xF, 0xD, 0xC, 0x9, 0x8, 0xA, 0xB],
        [0x2, 0x3, 0x1, 0x0, 0x5, 0x4, 0x6, 0x7, 0xD, 0xC, 0xE, 0xF, 0xA, 0xB, 0x9, 0x8],
        [0x3, 0x2, 0x0, 0x1, 0x4, 0x5, 0x7, 0x6, 0xC, 0xD, 0xF, 0xE, 0xB, 0xA, 0x8, 0x9],
        [0x4, 0x5, 0x7, 0x6, 0x3, 0x2, 0x0, 0x1, 0xB, 0xA, 0x8, 0x9, 0xC, 0xD, 0xF, 0xE],
        [0x5, 0x4, 0x6, 0x7, 0x2, 0x3, 0x1, 0x0, 0xA, 0xB, 0x9, 0x8, 0xD, 0xC, 0xE, 0xF],
        [0x6, 0x7, 0x5, 0x4, 0x1, 0x0, 0x2, 0x3, 0x9, 0x8, 0xA, 0xB, 0xE, 0xF, 0xD, 0xC],
        [0x7, 0x6, 0x4, 0x5, 0x0, 0x1, 0x3, 0x2, 0x8, 0x9, 0xB, 0xA, 0xF, 0xE, 0xC, 0xD],
        [0x8, 0x9, 0xB, 0xA, 0xF, 0xE, 0xC, 0xD, 0x7, 0x6, 0x4, 0x5, 0x0, 0x1, 0x3, 0x2],
        [0x9, 0x8, 0xA, 0xB, 0xE, 0xF, 0xD, 0xC, 0x6, 0x7, 0x5, 0x4, 0x1, 0x0, 0x2, 0x3],
        [0xA, 0xB, 0x9, 0x8, 0xD, 0xC, 0xE, 0xF, 0x5, 0x4, 0x6, 0x7, 0x2, 0x3, 0x1, 0x0],
        [0xB, 0xA, 0x8, 0x9, 0xC, 0xD, 0xF, 0xE, 0x4, 0x5, 0x7, 0x6, 0x3, 0x2, 0x0, 0x1],
        [0xC, 0xD, 0xF, 0xE, 0xB, 0xA, 0x8, 0x9, 0x3, 0x2, 0x0, 0x1, 0x4, 0x5, 0x7, 0x6],
        [0xD, 0xC, 0xE, 0xF, 0xA, 0xB, 0x9, 0x8, 0x2, 0x3, 0x1, 0x0, 0x5, 0x4, 0x6, 0x7],
        [0xE, 0xF, 0xD, 0xC, 0x9, 0x8, 0xA, 0xB, 0x1, 0x0, 0x2, 0x3, 0x6, 0x7, 0x5, 0x4],
        [0xF, 0xE, 0xC, 0xD, 0x8, 0x9, 0xB, 0xA, 0x0, 0x1, 0x3, 0x2, 0x7, 0x6, 0x4, 0x5]]

shifts = [[0x4, 0x5, 0x7, 0x6, 0x3, 0x2, 0x0, 0x1, 0xB, 0xA, 0x8, 0x9, 0xC, 0xD, 0xF, 0xE],
          [0x4, 0xB, 0xB, 0x4, 0xB, 0x4, 0x4, 0xB, 0xA, 0x5, 0x5, 0xA, 0x5, 0xA, 0xA, 0x5],
          [0xB, 0x6, 0x0, 0xD, 0xD, 0x0, 0x6, 0xB, 0x6, 0xB, 0xD, 0x0, 0x0, 0xD, 0xB, 0x6],
          [0xE, 0x5, 0x9, 0x2, 0x0, 0xB, 0x7, 0xC, 0x3, 0x8, 0x4, 0xF, 0xD, 0x6, 0xA, 0x1],
          [0x4, 0xE, 0x1, 0xB, 0xF, 0x5, 0xA, 0x0, 0x3, 0x9, 0x6, 0xC, 0x8, 0x2, 0xD, 0x7],
          [0xA, 0x4, 0x7, 0x9, 0x0, 0xE, 0xD, 0x3, 0xE, 0x0, 0x3, 0xD, 0x4, 0xA, 0x9, 0x7],
          [0xE, 0x6, 0xE, 0x6, 0xF, 0x7, 0xF, 0x7, 0xD, 0x5, 0xD, 0x5, 0xC, 0x4, 0xC, 0x4],
          [0x7, 0x1, 0xB, 0xD, 0xE, 0x8, 0x2, 0x4, 0x4, 0x2, 0x8, 0xE, 0xD, 0xB, 0x1, 0x7],
          [0xD, 0xB, 0x0, 0x6, 0x6, 0x0, 0xB, 0xD, 0xA, 0xC, 0x7, 0x1, 0x1, 0x7, 0xC, 0xA],
          [0xe, 0x1, 0x1, 0xe, 0x1, 0xe, 0xe, 0x1, 0x1, 0xe, 0xe, 0x1, 0xe, 0x1, 0x1, 0xe]]

def getmfkeys(uid):
    uid = uid.hex().upper() if type(uid) is bytes or bytearray else uid
    uid = "%08X" % uid if type(uid) is int else uid
    uid = uid.upper()
    keys=[b'K\x0b \x10|\xcb']
    for block in range(1,16):
        s=[int(x, 16) for x in '%s%02X' % (uid, block)]
        permuted='C2'
        for i in range(len(s)):
            value = shifts[i][s[0]]
            for j in range(1, i+1):
                value ^= shifts[i-j][0] ^ shifts[i-j][s[j]]
            permuted += '%X' % value
        crc64numStr = crc64(bytes.fromhex(permuted))
        keys.append(crc64numStr.to_bytes(8, byteorder='little')[:6])
    return keys

def createtoy(figurine=(0,0), uid=None):
    """Arguments:
    figurine    Figurine to emulate
                type: Figurine or (toytype, subtype) iterable
                toytype and subtype can be bytes or hex string or int
    uid         UID as hexa string, int or bytes
    Return:     Dump"""
    if type(figurine) is Figurine:
        toytype, subtype = figurine.toytype, figurine.subtype
    else:
        toytype, subtype = figurine
    d=Dump(bytes(1024), fmt=BIN)
    d.setuid(uid)
    d.settoytype(toytype)
    d.setsubtype(subtype)
    d.refresh()
    return d
