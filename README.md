PHP class for converting Fortigate config file to Mikrotik instruction for easy transition from Fortigate to Mikrotik

forti2mikro.php

NOTICE:
1. It will create three wan ports (wan1,wan2 and wan3) and the rest will be bridged lan ports
2. all passwords that are encoded will not be converted. Instead, there will be password=ENCODED text. Please, update passwords manually
3. chains in some firewall rules might be wrong, so please check them before execution
4. firewall rules with geo positions are not working
5. please, reset Mikrotik on factory defaults before executing instruction sets
6. please, take look at /system script blocks and enter them using GUI
7. Conversion works ONLY with UNENCRYPTED config file, so please export config accordinlgy

v0.1a 26.07.2023. by Vedran Blazevic (www.heliasc.com)

Installation:
1. put forti2mikro.php anywhere on your PHP or web server with PHP
2. put fortigate config file in the same directory where is class
3. edit test.php and change "convert" line with your config file
4. execute test.php from web browser or from cli

