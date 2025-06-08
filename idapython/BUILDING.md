```text
------------------------------------------------------
IDAPython - Python plugin for Interactive Disassembler
------------------------------------------------------
Building From Source
--------------------

REQUIREMENTS
------------

[Tested versions are in brackets]


 - IDA and IDA SDK [> 5.6]
   http://www.hex-rays.com/idapro/

 - Python 3.x
   http://www.python.org/

 - Simplified Wrapper Interface Generator (SWIG)
    - if you intend to build for Python 3.x: [4.0.1, with support for -py3-limited-api]

   Hex-Rays cannot guarantee support for IDAPython
   versions built with other versions of SWIG.

   If building for Python 3.x:
       You can obtain the correct version of swig like so:
         `git clone --branch py3-stable-abi https://github.com/idapython/swig.git swig-py3-stable-abi`,
       and then compile it.

       On Windows, please refer to the following instructions:
         `http://www.swig.org/Doc4.0/Windows.html#Windows_cygwin_mingw`
       On Linux or OSX,
          (On Ubuntu, you might want to install a couple of packages:
            `sudo apt install libpcre3-dev yacc bison automake autotools-dev patchelf -y`)

         `sh autogen.sh`, then
         `./configure --prefix=/my_path_to/swig-4.0.1-py3-install && make && make install`


 - Unix utilities (GNU patch on Windows):
   http://www.research.att.com/sw/tools/uwin/ or
   http://unxutils.sourceforge.net/  or
   http://www.cygwin.com/

 - GCC on Linux and Mac OS X [4.0.1, 4.1.3]
   Comes with your distribution

 - Microsoft Visual C on Windows [Microsoft Visual C++ 2008 Express Edition]
   http://msdn.microsoft.com/vstudio/express/visualc/

 - Cygwin (requires GNU make)

BUILDING
--------

Make sure all the needed tools (compiler, swig) are on the PATH.

1. Unpack the IDA SDK into:
   '.../idasdk74'

Note: the path you unpack the IDA SDK into cannot contain white spaces,
   or special characters (such as '(', etc...)


2. Making sure the SDK compiles:
   If you are on:
    - Windows: set environment variable __NT__=1
    - Linux: set environment variable __LINUX__=1
    - Mac OSX: set environment variable __MAC__=1

   then, run 'make'


3. Place the IDAPython sources into the SDK directory, such that the file:
   '.../idasdk74/plugins/idapython/BUILDING.txt' exists

   Note: To build with Hex-Rays decompiler support, you will need to copy
      .../ida_install/plugins/hexrays_sdk/include/hexrays.hpp -> .../idasdk74/include/hexrays.hpp

   Note: If you want to build for Python3 (let's say you are building for Python 3.8),
      please set the following environment variables:
      - export PYTHON_VERSION_MAJOR=3 ('set PYTHON_VERSION_MAJOR=3' on Windows)
      - export PYTHON_VERSION_MINOR=8 ('set PYTHON_VERSION_MINOR=8 on Windows)

4. Build the plugin

   python build.py --swig-home /my_path_to/swig-4.0.1-py3-install --with-hexrays --ida-install /path/to/ida_install/

   You can also run 'build.py --help' for more information.


5. Install the components as described in README.md


```
