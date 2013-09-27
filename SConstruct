# Written by Victor Grishchenko, Arno Bakker 
# see LICENSE.txt for license information
#
# Requirements:
#  - scons: Cross-platform build system    http://www.scons.org/
#  - libevent2: Event driven network I/O   http://www.libevent.org/
#    * Set install path below >= 2.0.17
# For unittests:
#  - googletest: Google C++ Test Framework http://code.google.com/p/googletest/
#       * Set install path in tests/SConscript
#


import os
import re
import sys

DEBUG = True
CODECOVERAGE = (DEBUG and True)

TestDir='tests'

target = 'swift'
source = [ 'bin.cpp', 'binmap.cpp', 'sha1.cpp','hashtree.cpp',
    	   'transfer.cpp', 'channel.cpp', 'sendrecv.cpp', 'send_control.cpp', 
    	   'compat.cpp','avgspeed.cpp', 'avail.cpp', 'cmdgw.cpp', 'httpgw.cpp',
           'storage.cpp', 'zerostate.cpp', 'zerohashtree.cpp',
           'api.cpp', 'content.cpp', 'live.cpp', 'swarmmanager.cpp', 'address.cpp']
# cmdgw.cpp now in there for SOCKTUNNEL

env = Environment()
if sys.platform == "win32":
    libevent2path = '\\build\\libevent-2.0.20-stable-debug'

    # "MSVC works out of the box". Sure.
    # Make sure scons finds cl.exe, etc.
    env.Append ( ENV = { 'PATH' : os.environ['PATH'] } )

    # Make sure scons finds std MSVC include files
    if not 'INCLUDE' in os.environ:
        print "swift: Please run scons in a Visual Studio Command Prompt"
        sys.exit(-1)
        
    include = os.environ['INCLUDE']
    include += libevent2path+'\\include;'
    include += libevent2path+'\\WIN32-Code;'
    env.Append ( ENV = { 'INCLUDE' : include } )
    
    if 'CXXPATH' in os.environ:
        cxxpath = os.environ['CXXPATH']
    else:
        cxxpath = ""
    cxxpath += include
    if DEBUG:
        env.Append(CXXFLAGS="/Zi /MTd")
        env.Append(LINKFLAGS="/DEBUG")
    else:
        env.Append(CXXFLAGS="/DNDEBUG") # disable asserts
    env.Append(CXXPATH=cxxpath)
    env.Append(CPPPATH=cxxpath)

    # getopt for win32
    source += ['getopt.c','getopt_long.c']
 
     # Set libs to link to
     # Advapi32.lib for CryptGenRandom in evutil_rand.obj
    libs = ['ws2_32','libevent','Advapi32'] 
        
    # Update lib search path
    libpath = os.environ['LIBPATH']
    libpath += libevent2path+';'

    # Somehow linker can't find uuid.lib
    libpath += 'C:\\Program Files\\Microsoft SDKs\\Windows\\v6.0A\\Lib;'

    # Make the swift.exe a Windows program not a Console program when used inside another prog
    linkflags = '/SUBSYSTEM:WINDOWS'
    if not DEBUG:
    	env.Append(LINKFLAGS=linkflags)
    
    linkflags = ''
    
    APPSOURCE=['swift.cpp','statsgw.cpp','getopt.c','getopt_long.c']
    
else:
    # Linux or Mac build
    
    libevent2path = '/home/vincent/svn/libswift/libevent21'

    # Enable the user defining external includes
    if 'CPPPATH' in os.environ:
        cpppath = os.environ['CPPPATH']
    else:
        cpppath = ""
        print "To use external libs, set CPPPATH environment variable to list of colon-separated include dirs"
    cpppath += libevent2path+'/include:'
    env.Append(CPPPATH=".:"+cpppath)
    #env.Append(LINKFLAGS="--static")

    #if DEBUG:
    #    env.Append(CXXFLAGS="-g")

    # Large-file support always
    env.Append(CXXFLAGS="-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE")

    # Set libs to link to
    libs = ['stdc++','libevent','pthread']
    if 'LIBPATH' in os.environ:
          libpath = os.environ['LIBPATH']
    else:
        libpath = ""
        print "To use external libs, set LIBPATH environment variable to list of colon-separated lib dirs"
    libpath += libevent2path+'/lib:'


    linkflags = '-Wl,-rpath,'+libevent2path+'/lib'
    env.Append(LINKFLAGS=linkflags);


    APPSOURCE=['swift.cpp','statsgw.cpp']

env.Append(LIBPATH=libpath);
    
if DEBUG:
    env.Append(CXXFLAGS="-DDEBUG")
   
env.StaticLibrary (
    target='libswift',
    source = source,
    LIBS=libs,
    LIBPATH=libpath )

env.Program(
   target='swift',
   source=APPSOURCE,
   #CPPPATH=cpppath,
   LIBS=[libs,'libswift'],
   LIBPATH=libpath+':.')

Export("env")
Export("libs")
Export("linkflags")
Export("DEBUG")
Export("CODECOVERAGE")
# Arno: uncomment to build tests
#SConscript('tests/SConscript')

