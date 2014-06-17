# Written by Arno Bakker
# see LICENSE.txt for license information
#
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
from sha import sha

from activatetest import TestDirSeedFramework
from testasserver import TestAsServer
from SwiftDef import SwiftDef
from swiftconn import *

DEBUG=False

def chunkspeccontain(big,small):
    if big == small:
        return False
    if big[0] <= small[0] and small[1] <= big[1]:
        return True
    else:
        return False


class TestLiveSourceUMTFramework(TestAsServer):
    """
    Framework for testing if live source's output is sane: munros and HAVEs 
    span a consecutive range (assuming no losses)
    """

    def setUpPreSession(self):
        TestAsServer.setUpPreSession(self)

        self.destdir = '.'

        f = open("liveinput.dat","wb")
        self.nchunks = 1017
        for i in range(0,self.nchunks):
            data = chr((ord('0')+i)%256) * 1024
            f.write(data)
        f.close()

        self.livesourceinput = "liveinput.dat"
        self.filename = "storage.dat"

        self.urlfilename = "swarm.url"
        self.livesigalg = ord(POPT_LSA_ECDSAP256SHA256)

        self.debug = True
        
        
    def setUpPostSession(self):
        TestAsServer.setUpPostSession(self)

        f = open(self.urlfilename,"rb")
        swarmurl = f.read()
        f.close()
        swarmurl = swarmurl.strip()
        idx = swarmurl.find("/")
        if idx == -1:
            self.assertFalse(True)
        else:
            liveswarmidhex = swarmurl[idx+1:]
            print >>sys.stderr,"test: SwarmID <"+liveswarmidhex+">"
            self.liveswarmid = binascii.unhexlify(liveswarmidhex)
        


    def tearDown(self):
        TestAsServer.tearDown(self)
        try:
            os.remove(self.livesourceinput)
        except:
            pass
        try:
            os.remove(self.filename)
        except:
            pass

    
    
class TestLiveSourceUMTTests: # subclassed below    
    """
    Actual test definitions 
    """

    
    def tst_monitor_source(self):
        myaddr = ("127.0.0.1",15357)
        hisaddr = ("127.0.0.1",self.listenport)
        
        # Let source start up
        time.sleep(.5)
        
        print >>sys.stdout,"test: Connect as peer"
        s = SwiftConnection(myaddr,hisaddr,self.liveswarmid,cipm=POPT_CIPM_UNIFIED_MERKLE,lsa=chr(self.livesigalg),cam=CHUNK_SPEC_ID_CHUNK32,ldw=POPT_LDW_ALL_CHUNK32)

        hashlist = []
        munrolist = []
        havelist = []
        recvflag=True        
        kacount = 0
        while True:
            try:
                d = s.recv()
            except socket.timeout:
                break
            while True:
                msg = d.get_message()
                if msg is None:
                    break
                print >>sys.stdout,"test: Got",`msg`
                if msg.get_id() == MSG_ID_HANDSHAKE:
                    s.c.set_his_chanid(msg.chanid)
                    self.send_keepalive(s)
                    
                elif msg.get_id() == MSG_ID_INTEGRITY:
                    newhash = (msg.chunkspec.s,msg.chunkspec.e)
                    hashlist = self.update_chunklist(newhash, hashlist,consec=False)
                    print >>sys.stdout,"test: hashlist",hashlist
                        
                elif msg.get_id() == MSG_ID_SIGNED_INTEGRITY:
                    newmunro = (msg.chunkspec.s,msg.chunkspec.e)
                    munrolist = self.update_chunklist(newmunro, munrolist,consec=False)
                    print >>sys.stdout,"test: munrolist",munrolist
                    
                    # Each SIGNED_INTEGRITY must be preceded by its INTEGRITY message
                    self.assertEquals(hashlist,munrolist)

                    # All munros must be covered by HAVE                    
                    for munro in munrolist:
                        found = False
                        for have in havelist:
                            if chunkspeccontain(have,munro) or (munro == have):
                                found = True
                                break
                        if not found:
                            x = `havelist`
                            print >>sys.stderr,"test: UNCOVERED MUNRO"+str(have)+" in havelist "+x
                            print >>sys.stdout,"test: UNCOVERED MUNRO",have,"in havelist",munrolist
                        self.assertTrue(found)


                elif msg.get_id() == MSG_ID_HAVE:
                    newhave = (msg.chunkspec.s,msg.chunkspec.e)
                    havelist = self.update_chunklist(newhave, havelist)
                    print >>sys.stdout,"test: havelist",havelist

                kacount += 1
                if (kacount % 100) == 0:
                    self.send_keepalive(s)

        self.assertTrue(len(munrolist) > 0)
        self.assertTrue(len(havelist) > 0)

        # Send explicit close
        d = s.makeDatagram()
        d.add( HandshakeMessage(CHAN_ID_ZERO,POPT_VER_PPSP) )
        s.c.send(d)

    def update_chunklist(self,newchunk,chunklist,consec=True):
        templist = []
        added=False
        for chunk in chunklist:
            if newchunk == chunk:
                templist.append(chunk)
                added = True
            elif not chunkspeccontain(newchunk,chunk): # new doesn't subsume old
                templist.append(chunk)
            elif not added:
                templist.append(newchunk)
                added = True
        if not added:
            templist.append(newchunk)
        olde = -1
        
        if consec:
            for chunk in templist:
                (start,end) = chunk
                if olde != -1:
                    self.assertEquals(olde+1,start)
                olde = end
        return templist

        

    def send_keepalive(self,s):
        print >>sys.stdout,"test: Send keep alive"            
        d2 = s.makeDatagram()
        d2.add( KeepAliveMessage() )
        s.c.send(d2)



class TestLiveSourceUMTLiveDiscardNone(TestLiveSourceUMTFramework,TestLiveSourceUMTTests):
    """
    Test live source with live discard window None (i.e., source remembers all)
    """
    def test_monitor_source(self):
        self.tst_monitor_source()


class TestLiveSourceUMTLiveDiscardWrap(TestLiveSourceUMTFramework,TestLiveSourceUMTTests):
    """
    Test live source with live discard window set. Should give same output
    as with no discard window.
    """
    def setUpPreSession(self):
        TestLiveSourceUMTFramework.setUpPreSession(self)
        
        self.livediscardwindow = 128

    def test_monitor_source(self):
        self.tst_monitor_source()

        
        
def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLiveSourceUMTLiveDiscardNone))
    #suite.addTest(unittest.makeSuite(TestLiveSourceUMTLiveDiscardWrap))
    return suite


def main():
    unittest.main(defaultTest='test_suite',argv=[sys.argv[0]])

if __name__ == "__main__":
    main()

            