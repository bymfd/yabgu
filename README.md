# yabgu
Zerossl acme client for apache and plesk panels usable *nix and Windows 



## How to use:
 - Clone this repo
 - Install requipments
 - Edit config.ini
 - `` python yabgu.py -s example.com ``
 - Optional (make executable directly with pyinstaller )

## Apache:
 - Edit config.ini with your apache configration
 - Leave blank deploy area
 
## Plesk:
 - Edit config.ini with your plesk configration
 - Choose a directory store certs.
 - Sure directory r/w permisson for program
## Windows:
 - Yes supported windows.
## Parameters:
 |   	| parameter 	| short 	| summary                                    	| example              	|
|---	|-----------	|-------	|--------------------------------------------	|----------------------	|
| ✔️ 	| --site    	| -s    	| wanted add cert. domain name               	| yabgu -s example.com 	|
| ⚙️ 	| --list    	| -l    	| List of added domains.(WIP)                	| yabgu -l a           	|
| ⚙️ 	| --renew   	| -r    	| Control domain exp. dates and renew certs.(WIP) 	| yagbu -r 0           	|
| ⚙️ 	| --remove   	| -rm    	| Revoke and Remove certs.(WIP) 	| yagbu -rm example.com          	|

## TODO:
- write more detailed how to use.
- Revoke certs.
- List added certs.
- More handle api errors
