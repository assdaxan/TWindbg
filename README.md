[![Python 3](https://img.shields.io/badge/Python-3-green.svg)](https://github.com/assdaxan/TWindbg)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](http://choosealicense.com/licenses/mit/)

# TWindbg for WinDbg-Preview
PEDA-like debugger UI for WinDbg-Preview

* JMP Highlight
![context img](/img/jmp_image.png?raw=true)

* Navigator
![context img](/img/navigator_image.png?raw=true)

# Original Repository
* [TWindbg](https://github.com/bruce30262/TWindbg)

# Introduction
This is a windbg extension ( using [pykd](https://githomelab.ru/pykd/pykd) ) to let user having a [PEDA-like](https://github.com/longld/peda) debugger UI in WinDbg.  
It will display the following context in each step/trace:  
- Registers
- Disassembled code near PC
- Contents of the stack pointer ( with basic smart dereference )  

It also supports some peda-like commands ( see the [support commands](#support-commands) section )

For now it supports both x86 & x64 WinDbg.

# Dependencies
* Python 3  

> I decided to drop the support of Python2.7 since it has [reached the EOL](https://www.python.org/doc/sunset-python-2/). I believe the project is Python2/3 compatible, however there might exist some issues in pykd and can cause different behavior in Python2/3. Since now the project will only be tested on Python3, I strongly suggest using TWindbg on Python3 instead of Python 2.7. If you still want to use it on Python 2.7, feel free to fork the project and do the development.

* [pykd](https://githomelab.ru/pykd/pykd)

# Installation
* Install Python3
* Add Windows System PATH 
    - Variable Name : `PATH`
    - Variable Value : `%LOCALAPPDATA%\Dbg\EngineExtensions\`
* Install pykd  
    - Download [Pykd-Ext](https://githomelab.ru/pykd/pykd-ext/-/wikis/Downloads), unpack `pykd.dll` to the `%LOCALAPPDATA%\Dbg\EngineExtensions\` directory.  
        + This will allow you to run python in Windbg.  
    - In the Windbg command line, enter command `.load pykd` to load the pykd module.  
    - Enter `!pip install pykd` to install the pykd python package.  
        + Upgrade the pykd module with command `!pip install --upgrade pykd`.  
        + If something went wrong during the installation with `pip install`, try installing the wheel package instead of the one on PyPI. You can download the wheel package [here](https://githomelab.ru/pykd/pykd/-/wikis/All%20Releases).
* Download the repository
* Copy the [TWindbg](/TWindbg) folder into `%LOCALAPPDATA%\Dbg\EngineExtensions\` & `%LOCALAPPDATA%\Dbg\EngineExtensions32\`

# Usage
## Launch TWindbg manually
* Open an executable or attach to a process with WinDbg
* Use `.load pykd` to load the `pykd` extension
* Use `!py -g TWindbg\TWindbg.py` to launch TWindbg

# Support Commands
* `TWindbg`: List all the command in TWindbg
* `ctx`: Print out the current context
* `tel / telescope`: Display memory content at an address with smart dereferences

# Note
Maybe ( just maybe ) I'll add more command to make WinDbg behave more like PEDA ( or other debugger like pwndbg, GEF... ) in the future.