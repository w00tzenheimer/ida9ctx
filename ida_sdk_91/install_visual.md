```text


Please read "readme.txt" before reading this file!


How to set up Visual C++ 2019 for IDA Plugins
---------------------------------------------

This guide will help you set up a Visual C++ project that targets ida plugins.
Plugins must be built for the x64 platform.

1. File | New | Project From Existing Code...

2. What type of project would you like to create: Visual C++
   <next>

3. Project file location: <folder where you have your files>
   Project name: <your plugin's name>
   <finish>

Once the project is initialized, right-click on the project name and pick Properties.

4. Configuration Manager...
     Active solution platform: You can remove the "x86" platform by clicking "Edit" and removing it.
     Active solution platform: select "x64"
   <Close>

5. General | Project Defaults | Configuration Type
     Dynamic Library (.dll)
   <apply>

6. C/C++ | General | Additional Include Directories
     Enter the SDK's include folder in "Include search paths (/I)": eg. C:\idasdk\include;
   <apply>

7. C/C++ | Code Generation | Runtime library (visible only after you add one .cpp file to the project)
     Multi-threaded DLL (/MD)
   <apply>

8. Linker | Command Line | Additional options
     - for processor modules: /EXPORT:LPH
     - for plugins: /EXPORT:PLUGIN
     - for loaders: /EXPORT:LDSC
   <apply>

We will now create the configurations.

9. Still under "Configuration Manager..."

     - under the "Configuration" column, click on "Debug"
     - click "<Edit...>"
     - click "Rename"
     - add an "ida" prefix to the configuration name, such as "ida Debug"
     - <Enter>
     - <Yes>
     - <Close>

     - under "Active solution configuration", click on "Debug"
     - click "<Edit...>"
     - click "Rename"
     - add an "ida" prefix to the configuration name, such as "ida Debug"
     - <Enter>
     - <Yes>
     - <Close>

In the "Property Page", under "Configuration", select "ida Debug".

10. Debugging | Command
      - C:\Program Files\IDA 9.0\ida.exe
    <apply>

11. C/C++ | Preprocessor | Preprocessor Definitions
      - __NT__;__EA64__;
    <apply>

12. Linker | General | Output File:
      - $(OutDir)\$(ProjectName).dll
    <apply>

13. Linker | Input | Additional Dependencies
      - C:\idasdk\lib\x64_win_vc_64\ida.lib
    <apply>


You should now be capable to easily build your project in debug mode.

```
