# Written by Arno Bakker
#
# see LICENSE.txt for license information

import unittest

import os
import sys
import tempfile
import random
import shutil
import time
import subprocess
import urllib2
import string
import binascii
from traceback import print_exc

from testasserver import TestAsServer
from SwiftDef import SwiftDef

DEBUG=True


def bytestr2int(b):
    if b == "":
        return None
    else:
        return int(b)
    
    
def rangestr2triple(rangestr,length):
    # Handle RANGE query
    bad = False
    type, seek = string.split(rangestr,'=')
    if seek.find(",") != -1:
        # - Range header contains set, not supported at the moment
        bad = True
    else:
        firstbytestr, lastbytestr = string.split(seek,'-')
        firstbyte = bytestr2int(firstbytestr)
        lastbyte = bytestr2int(lastbytestr)

        if length is None:
            # - No length (live) 
            bad = True
        elif firstbyte is None and lastbyte is None:
            # - Invalid input
            bad = True
        elif firstbyte >= length:
            bad = True
        elif lastbyte >= length:
            if firstbyte is None:
                """ If the entity is shorter than the specified 
                suffix-length, the entire entity-body is used.
                """
                lastbyte = length-1
            else:
                bad = True
        
    if bad:
        return (-1,-1,-1)
    
    if firstbyte is not None and lastbyte is None:
        # "100-" : byte 100 and further
        nbytes2send = length - firstbyte
        lastbyte = length - 1
    elif firstbyte is None and lastbyte is not None:
        # "-100" = last 100 bytes
        nbytes2send = lastbyte
        firstbyte = length - lastbyte
        lastbyte = length - 1
        
    else:
        nbytes2send = lastbyte+1 - firstbyte

    return (firstbyte,lastbyte,nbytes2send)
    
    
    

class TstMultiFileSeekFramework(TestAsServer):
    """
    Framework for multi-file swarm tests, consisting of HTTP GET Range requests
    to the various files in the multi-file swarm.
    """

    def setUpPreSession(self):
        TestAsServer.setUpPreSession(self)
        self.destdir = tempfile.mkdtemp()
        
        print >>sys.stderr,"test: destdir is",self.destdir
        
        self.setUpFileList()
        
        idx = self.filelist[0][0].find("/")
        specprefix = self.filelist[0][0][0:idx]
        
        prefixdir = os.path.join(self.destdir,specprefix)
        os.mkdir(prefixdir)

        sdef = SwiftDef()
        
        # Create content
        for fn,s in self.filelist:
            osfn = fn.replace("/",os.sep)
            fullpath = os.path.join(self.destdir,osfn)
            f = open(fullpath,"wb")
            data = fn[len(specprefix)+1] * s
            f.write(data)
            f.close()
            
            sdef.add_content(fullpath,fn)

        self.specfn = sdef.finalize(self.binpath,destdir=self.destdir)
        f = open(self.specfn,"rb")
        self.spec = f.read()
        f.close()
        
        self.swarmid = sdef.get_id()
        print >>sys.stderr,"test: setUpPreSession: roothash is",binascii.hexlify(self.swarmid)
        
        self.mfdestfn = os.path.join(self.destdir,binascii.hexlify(self.swarmid))
        shutil.copyfile(self.specfn,self.mfdestfn)
        shutil.copyfile(self.specfn+".mhash",self.mfdestfn+".mhash")
        shutil.copyfile(self.specfn+".mbinmap",self.mfdestfn+".mbinmap")
        

    def setUpFileList(self):
        self.filelist = []
        # Minimum 1 entry

    def setUpPostSession(self):
        TestAsServer.setUpPostSession(self)
        
        #CMD = "START tswift:/"+binascii.hexlify(self.swarmid)+" "+self.destdir+"\r\n"
        CMD = "START tswift://127.0.0.1:"+str(self.listenport)+"/"+binascii.hexlify(self.swarmid)+" "+self.destdir+"\r\n"
        self.cmdsock.send(CMD)
        
        self.urlprefix = "http://127.0.0.1:"+str(self.httpport)+"/"+binascii.hexlify(self.swarmid)

    def tst_read_all(self):
        print >>sys.stderr,"test: tst_read_all"
        
        url = self.urlprefix        
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req)
        data = resp.read()
        
        # Read and compare content
        if data[0:len(self.spec)] != self.spec:
            self.assert_(False,"returned content doesn't match spec")
        offset = len(self.spec)
        for fn,s in self.filelist:
            osfn = fn.replace("/",os.sep)
            fullpath = os.path.join(self.destdir,osfn)
            f = open(fullpath,"rb")
            content = f.read() 
            f.close()
            
            if data[offset:offset+s] != content:
                self.assert_(False,"returned content doesn't match file "+fn )
                
            offset += s
        
        self.assertEqual(offset, len(data), "returned less content than expected" )
        

    def tst_read_file0(self):
        print >>sys.stderr,"test: tst_read_file0"
        
        wanttup = self.filelist[0]
        self._tst_read_file(wanttup)

    def tst_read_file1(self):
        print >>sys.stderr,"test: tst_read_file1"
        
        if len(self.filelist) > 1:
            wanttup = self.filelist[1]
            self._tst_read_file(wanttup)
        
    def tst_read_file2(self):
        print >>sys.stderr,"test: tst_read_file2"
        if len(self.filelist) > 2:
            wanttup = self.filelist[2]
            self._tst_read_file(wanttup)

    def _tst_read_file(self,wanttup):
        url = self.urlprefix+"/"+wanttup[0]    
        req = urllib2.Request(url)
        resp = urllib2.urlopen(req)
        data = resp.read()
        resp.close()
        
        osfn = wanttup[0].replace("/",os.sep)
        fullpath = os.path.join(self.destdir,osfn)
        f = open(fullpath,"rb")
        content = f.read() 
        f.close()
            
        if data != content:
            self.assert_(False,"returned content doesn't match file "+osfn )
                
        self.assertEqual(len(content), len(data), "returned less content than expected" )

    def tst_read_file0_range(self):
        print >>sys.stderr,"test: tst_read_file0_range"
        
        wanttup = self.filelist[0]
        self._tst_read_file_range(wanttup,"-2")
        self._tst_read_file_range(wanttup,"0-2")
        self._tst_read_file_range(wanttup,"2-")
        self._tst_read_file_range(wanttup,"4-10")

    def tst_read_file1_range(self):
        print >>sys.stderr,"test: tst_read_file1_range"
        
        if len(self.filelist) > 1:
            wanttup = self.filelist[1]
            self._tst_read_file_range(wanttup,"-2")
            self._tst_read_file_range(wanttup,"0-2")
            self._tst_read_file_range(wanttup,"2-")
            self._tst_read_file_range(wanttup,"4-10")

    def tst_read_file2_range(self):
        print >>sys.stderr,"test: tst_read_file2_range"
        
        if len(self.filelist) > 2:
            wanttup = self.filelist[2]
            self._tst_read_file_range(wanttup,"-2")
            self._tst_read_file_range(wanttup,"0-2")
            self._tst_read_file_range(wanttup,"2-")
            self._tst_read_file_range(wanttup,"4-10")


    def _tst_read_file_range(self,wanttup,rangestr):
        url = self.urlprefix+"/"+wanttup[0]    
        req = urllib2.Request(url)
        val = "bytes="+rangestr
        req.add_header("Range", val)
        (firstbyte,lastbyte,nbytes) = rangestr2triple(val,wanttup[1])
            
        print >>sys.stderr,"test: Requesting",firstbyte,"to",lastbyte,"total",nbytes,"from",wanttup[0]
            
        resp = urllib2.urlopen(req)
        data = resp.read()
        resp.close()
        
        osfn = wanttup[0].replace("/",os.sep)
        fullpath = os.path.join(self.destdir,osfn)
        f = open(fullpath,"rb")
        content = f.read() 
        f.close()
            
        #print >>sys.stderr,"test: got",`data`
        #print >>sys.stderr,"test: want",`content[firstbyte:lastbyte+1]`
            
        if data != content[firstbyte:lastbyte+1]:
            self.assert_(False,"returned content doesn't match file "+osfn )
                
        self.assertEqual(nbytes, len(data), "returned less content than expected" )


class TestMFSAllAbove1K(TstMultiFileSeekFramework):
    """ 
    Concrete test of files all > 1024 bytes
    """

    def setUpFileList(self):
        self.filelist = []
        self.filelist.append(("MyCollection/anita.ts",1234))
        self.filelist.append(("MyCollection/harry.ts",5000))
        self.filelist.append(("MyCollection/sjaak.ts",24567))

    def test_read_all(self):
        self.tst_read_all()

    def test_read_file0(self):
        self.tst_read_file0()

    def test_read_file1(self):
        self.tst_read_file1()
        
    def test_read_file2(self):
        self.tst_read_file2()

    def test_read_file0_range(self):
        self.tst_read_file0_range()

    def test_read_file1_range(self):
        self.tst_read_file1_range()

    def test_read_file2_range(self):
        self.tst_read_file2_range()


class TestMFS1stSmall(TstMultiFileSeekFramework):
    """ 
    Concrete test with 1st file fitting in 1st chunk (i.e. spec+file < 1024)
    """
    def setUpFileList(self):
        self.filelist = []
        self.filelist.append(("MyCollection/anita.ts",123))
        self.filelist.append(("MyCollection/harry.ts",5000))
        self.filelist.append(("MyCollection/sjaak.ts",24567))

    def test_read_all(self):
        self.tst_read_all()

    def test_read_file0(self):
        self.tst_read_file0()

    def test_read_file1(self):
        self.tst_read_file1()
        
    def test_read_file2(self):
        self.tst_read_file2()

    def test_read_file0_range(self):
        self.tst_read_file0_range()

    def test_read_file1_range(self):
        self.tst_read_file1_range()

    def test_read_file2_range(self):
        self.tst_read_file2_range()


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestMFSAllAbove1K))
    suite.addTest(unittest.makeSuite(TestMFS1stSmall))
    
    return suite


def main():
    unittest.main(defaultTest='test_suite',argv=[sys.argv[0]])

if __name__ == "__main__":
    main()

        