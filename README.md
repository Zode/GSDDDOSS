# GSDDDOSS (GoldSource Denied Distributed Denial of Service Script)
GSDDDOSS is a simple python script that monitors your goldsrc/svengine game server's udp log output for the following attacks:
Bad Rcon,
Split Packets,
and A2S abuse / Reflected DDoS

Any ip associated with any of these attacks will be automagically blocked in the firewall.

(blame H2 for the name :P)

If you find a bug, or have improved on the script - feel free to make a pull request!

## Requirements:
python 3.6 or greater.

## Support:
Windows (tested)

Linux (untested, but should work)

## Installation:
Download & run the script, it will automatically start listening on udp port 8008.
In your server.cfg file add the line: ```logaddress_add 127.0.0.1 8008```

and either restart the server, or rcon the same line in the server console.

note: ideally you wanna run the python command in a loop in case it crashes or something, use screen or tmux on linux.

## Windows .bat trick for lazy administrator:
(this assumes python3 is added in PATH)

Make a new .bat file containing:
```
@echo off
title GSDDDOSS
:watch
python gsdddoss.py
goto watch
```
After that make a shortcut to the bat file, and go to the shortcut properties.

In the shortcut properties find the button labeled "Advanced" and tick off "Run as administrator".

Then you just run the shortcut and press yes during UAC