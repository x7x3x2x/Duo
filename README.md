<h1 align="center">
	<img src="https://icons.veryicon.com/png/o/emoticon/number/duo-1.png" width="150px"><br>
    Duo - A post-exploitation framework for Windows and Linux.
</h1>
<p align="center">
	Duo is a post-exploitation framework that supports both Windows and Linux. It comes with all the scripts and tools you need for post-exploitation.
</p>

<p align="center">
	<a href="https://deno.land" target="_blank">
    	<img src="https://img.shields.io/badge/Version-1.0.0-7DCDE3?style=for-the-badge" alt="Version">
</p>

## Features
```
Windows:
 - Over 35 scripts
 - Modules for extra enumeration
 - WSL acess and options for loading reverse/bind shell code into WSL
 - Options to navigate around in CMD and Powershell

Linux:
 - Over 15 scripts
 - Options to navigate around the terminal

Payload_Factory:
 - 10 different payloads
 - Support for both Windows and Linux
```
## Installation
```
pip3 install requests
pip3 install colorama
python duo.py
```

## Arguments/Options
Duo has a several arguments/options for custom launching just incase something happens. These options can also assist in getting Duo to work if there are any issues. You can also launch the Payload Factory to start generating payloads!
```
╭─user@workspace in ~/Desktop/g/Duo 
╰─λ python duo.py --help

-h, --help       Displays commands.
-d, --duo        Launches the Duo Framework. [The Appropriate framework will be launched after an OS check.]
-l, --linux      Launches Duo Framework for Linux.
-w, --windows    Launches Duo Framework for Windows.
-p, --payload    Launches the Payload Factory.
```

## Credits
```
https://github.com/0x1CA3
```
### Contributions 🎉
###### All contributions are accepted, simply open an Issue / Pull request.
