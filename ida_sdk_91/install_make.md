```text


Please read "readme.txt" before reading this file!


Preparing the build environment on MS Windows
---------------------------------------------

  Prerequisites
  =============

  In addition to the compiler specified in readme.txt, Cygwin is required
  on MS Windows. It is available from:

    https://www.cygwin.com/

  64-bit version of Cygwin (setup-x86_64.exe) is recommended, as the 32-bit
  one may produce errors during multi-threaded builds. Make sure to install
  the 'make' package.


  Build environment
  =================

  On MS Windows, you may build the SDK using either the Cygwin shell or the
  Command Prompt (either cmd.exe or a Developer Command Prompt for Visual
  Studio).

  If you wish to use the Cygwin shell to build the SDK, start it with:

    > C:\cygwin\cygwin.bat

  If you wish to use the Command Prompt, you must add Cygwin's bin directory
  to your PATH:

    > set PATH=C:\cygwin64\bin;%PATH%

  You should then navigate to IDA's SDK directory, for example:

    > cd C:\idasdk

  Then you should setup the Visual C++ environment. For that, set the
  VCINSTALLDIR environment variable or update it in defaults.mk.
  For example:

    C:\idasdk> set VCINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\

  The MS Windows build automatically generates a configuration file from the
  top-level directory of the SDK. To build this configuration file directly,
  invoke make for the desired target from the top-level directory with, e.g.:

    C:\idasdk> bin\m.bat env

  or, in a cygwin shell:

    /cygdrive/c/idasdk $ bin\m.bat env

  If this file is not generated, you will hit this error message:

    cl : Command line error D8022 : cannot open '../../x64_win_vc_32.cfg'

  If you want to build the debug servers, you should specify the path to
  Microsoft Windows SDK v7.1. For example:

    C:\idasdk> set MSSDK71_PATH="C:\Program Files\Microsoft SDKs\Windows\v7.1"

  Note the quotes around the path.


  Preparing the SDK
  =================

  Add the SDK's bin directory to your PATH.

  On MS Windows' Command Prompt:

    C:\idasdk>set PATH=C:\idasdk\bin;%PATH%

  or, in a cygwin shell:

    /cygdrive/c/idasdk $ export PATH=/cygdrive/c/idasdk/bin:$PATH

    (please note that the separator is ':' here, not ';' as in cmd.exe)


Preparing the build environment on Linux and macOS
--------------------------------------------------

  Add the SDK's bin directory to your PATH.

    $ export PATH=~/idasdk/bin:$PATH


Target platform
---------------

  The target platform must be specified using one of the following environment
  variables:

    - MS Windows: __NT__
    - Linux:      __LINUX__
    - macOS:      __MAC__ (and __ARM__ if building for an arm64 macOS)

  If no target platform is specified, the build defaults to MS Windows (__NT__).

  It is a good idea to specify the platform directly on your ~/.bashrc file:
    - MS Windows (Cygwin):
      export __NT__=1
    - Linux:
      export __LINUX__=1
    - macOS:
      export __MAC__=1
      export __ARM__=1 # if needed (for Apple Silicon)


How to build the SDK from the command-line
------------------------------------------

  All source files are the same for all platforms and are compiled using the
  same makefiles. The build commands are different between operating systems.


  On Linux and macOS
  ==================

  It should suffice to invoke 'make' directly:

    make

  If you did not export the target platform's environment variable, you can
  specify the target in the command line, for example:

    make __LINUX__=1
    make __MAC__=1 __ARM__=1


  To build for IDA:

    make


  To build 32-bit (x86) debug servers, you must set the __X86__ variable. This can
  be achieved in the command line with:

    make __EA32__=1 __X86__=1

  You may also run the 'idamake.pl' script instead of 'make'. It is a post-
  processing script for make, and will filter out some warnings
  which cannot be disabled in the compiler. For example, there is this warning
  from gcc:

    warning: format ‘%a’ expects argument of type ‘double’, but argument 2 has type ‘ea_t {aka unsigned int}’ [-Wformat=]

  An environment option IDAMAKE_SIMPLIFY can be passed to
  'idamake.pl' to turn on filtering of compiler command lines.

  Some examples:

    make __LINUX__=1                    -- non-optimized linux build
    make NDEBUG=1 __MAC__=1 __ARM__=1   -- optimized mac (arm64) build
    make NDEBUG=1 __NT__=1              -- optimized ida windows build
    IDAMAKE_SIMPLIFY=1 idamake.pl [...] -- filter build system output


  On MS Windows
  =============

  The build target is selected by using special bat files, present in the bin/
  directory

    mo.bat    - will build components for ida.exe
    mso.bat   - will build win64_remote64.exe
    mso32.bat - will build win32_remote.exe

  They accept a '-j' argument, to parallelize the build:

  E.g.:

    C:\idasdk>mo.bat -j 12

  or, in a Cygwin shell:

    /cygdrive/c/idasdk $ mo.bat -j 12

Aliases
-------

  Creating aliases for the build commands is a good idea. I have the following
  in my .bashrc file:

  export __LINUX__=1
  export PATH=~/idasdk/bin:$PATH
  alias m='idamake.pl 2>&1'
  alias mo='NDEBUG=1 m'

```
