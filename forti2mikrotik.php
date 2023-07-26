<?php

/******************************************************************************************************************************************
forti2mikro.php class 
for converting Fortigate config file to Mikrotik instruction for easy transition from Fortigate to Mikrotik

NOTICE:
1. It will create three wan ports (wan1,wan2 and wan3) and the rest will be bridged lan ports
2. all passwords that are encoded will not be converted. Instead, there will be password=ENCODED text. Please, update passwords manually
3. chains in some firewall rules might be wrong, so please check them before execution
4. firewall rules with geo positions are not working
5. please, reset Mikrotik on factory defaults before executing instruction sets
6. please, take look at /system script blocks and enter them using GUI
7. Conversion works ONLY with UNENCRYPTED config file, so please export config accordinlgy

v0.1a 26.07.2023. by Vedran Blazevic (www.heliasc.com)

*******************************************************************************************************************************************/

class forti2mikro {
	

	// converts for eg. 255.255.255.0 to 16
	private function mask2cidr($mask) {
		$dq = explode(".",$mask);
		for ($i=0; $i<4 ; $i++) {
		   $bin[$i]=str_pad(decbin($dq[$i]), 8, "0", STR_PAD_LEFT);
		}
		$bin = implode("",$bin); 

		return strlen(rtrim($bin,"0"));
	}
	
	// $srcdest = 'src' or 'dst'
	private function get_address($mt,$mykey,$srcdst)
	{
		$s = "";
		foreach ($mt['config']['firewall address'] as $key=>$value) {							
				if ($key==$mykey) {				
					if (isset($value['subnet'])) {		
						$s = " ".$srcdst."-address=".explode(' ',$value['subnet'])[0].'/'.$this->mask2cidr(explode(' ',$value['subnet'])[1]);							
					}
					if (isset($value['start-mac'])) {					
						$s = " ".$srcdst."-mac-address=".$value['start-mac'];
					}
					if (isset($value['fqdn'])) {										
						$s = " ".$srcdst."-address=".$value['fqdn'];
					}						
				}			
		}	
		// if it is empty, search in groups
		$i=0;
		foreach ($mt['config']['firewall addrgrp'] as $key=>$value) {			
			if ($key==$mykey) {		
				$s = "";	$i=0;		
				foreach (explode(' ',$value['member']) as $member) {				
					$moj = $this->get_address($mt,$member,$srcdst);
					if (($i>0) && (!empty($moj))) {
						$moj = explode('=',$moj)[1];
						$s .= $moj.',';
					} else				
					if (!empty($moj)) { $s .= $moj.','; $i++; }
				}
				$s = rtrim($s,',');			
			}
		}	
		return $s;
	}	


	// $file is full path to fortigate config file
	// $lf is linefeed and can be "".$lf or "\n" or ""
	public function convert($file,$lf="<br>") {

		if (file_exists($file)) { $file = file_get_contents($file); }
		else { die(); }
		
		$arr = explode("\n",$file);

		// remove comments and whitespace
		foreach($arr as $key => $value) {
		  if (substr($value,0,1)=='#') {
			unset($arr[$key]);
		  }
		  $s = str_replace('  ','',$value);
		  $s = str_replace('[','',$s);
		  $s = str_replace(']','',$s);
		  $arr[$key] = $s;
		}


		// parse array and define associative array
		$mt = array();
		$edit_arr = array();
		$con = '';
		$edit = '';
		foreach($arr as $row)
		{	
			if (strpos($row,'config ') !== false) {
				// config end loop
				$con = substr($row,7);				
				$edit = '';
			} else
			if (strpos($row, 'end') == false) {		
				if ($row!='end') { 
					if (strpos($row,'edit ') !== false) {
						// edit next loop
						$edit = str_replace('"','',substr($row,5));							
						$edit = str_replace(' ','',$edit);											
						$edit_arr = array();
					} else {											
						
						if ((!empty($edit)) && ($row!='next')) { 									
							if (strpos($row,'set ') !== false) {
								$ss = explode(' ',$row);
								$sp = '';
								for($offset=2;$offset<count($ss);$offset++) { $sp.=$ss[$offset].' '; }
								$sp = rtrim($sp, " ");
								$edit_arr[$ss[1]]=(isset($ss[2])) ? str_replace('"','',$sp) : '';
							} else { 
								$edit_arr[] = $row;
							 }
						} else
						if ((!empty($edit)) && ($row=='next')) { $mt['config'][$con][$edit] = $edit_arr; $edit = ''; } else
						{ 
							if ($row!='next') { 
								if (strpos($row,'set ') !== false) {
									$ss = explode(' ',$row);
									$sp = '';
									for($offset=2;$offset<count($ss);$offset++) { $sp.=$ss[$offset].' '; }
									$sp = rtrim($sp, " ");
									$mt['config'][$con][$ss[1]] = (isset($ss[2])) ? str_replace('"','',$sp) : '';
								} else {
									$mt['config'][$con][] = $row; 
								}						
							} 
						}
					}
					
				}
			} 
		}
				

		// convert fortinet to mikrotik terminal commands
		// $s ="/system reset-configuration".$lf;
		// hostname
		$s .="/system identity set name=".$mt['config']['system global']['hostname'].$lf;

		// set interface names
		// first three will be reserved for wan (wan1,wan2,wan3), fourth will be lan
		// the rest names will be taken from configuration
		$s .="/interface set 0 name=wan1".$lf;
		$s .="/interface set 1 name=wan2".$lf;
		$s .="/interface set 2 name=wan3".$lf;
		$s .="/interface set 3 name=lan".$lf;

		// remove wan1,wan2 and wan3 from bridge
		$s .="/interface bridge port remove [ find interface=wan1 ]".$lf;
		$s .="/interface bridge port remove [ find interface=wan2 ]".$lf;
		$s .="/interface bridge port remove [ find interface=wan3 ]".$lf;

		// set ip address of the device
		// new ip will be on lan (port 4)
		$s .="/ip address remove 0".$lf;
		$addr = explode('.',$mt['config']['system interface']['lan']['ip']);
		$s .="/ip address add address=".str_replace(" 255.255.255.0","",$mt['config']['system interface']['lan']['ip'])."/24 interface=lan network=".$addr[0].".".$addr[1].".".$addr[2].".0".$lf;

		$internet_wan = "";

		// setup wan1
		if (isset($mt['config']['system interface']['wan1'])) {
			$pppoe = false;
			if (isset($mt['config']['system interface']['wan1']['mode'])) {	
				if ($mt['config']['system interface']['wan1']['mode']=='pppoe') {		
					$pppoe=true;
				}
			}
			if ($pppoe==true) { 
				$passwd = $mt['config']['system interface']['wan1']['password'];
				$passwd = (strpos($passwd, 'ENC') !== false) ? 'ENCODED' : $passwd;
				$s.="/interface pppoe-client add name=pppoe-user1 user=".$mt['config']['system interface']['wan1']['username']." password=".$passwd." interface=wan1 service-name=".$mt['config']['system interface']['wan1']['alias']." disabled=no".$lf;
			} else {
				$mt['config']['system interface']['wan1']['ip'] = str_replace(" 255.255.255.0","",$mt['config']['system interface']['wan1']['ip']);
				$s .="/ip address add address=".str_replace(" 255.255.255.0","",$mt['config']['system interface']['wan1']['ip'])."/24 interface=wan1".$lf;	
			}
			if (strtolower($mt['config']['system interface']['wan1']['alias'])=='internet') { $internet_wan = "wan1"; }
		}

		// setup wan2
		if (isset($mt['config']['system interface']['wan2'])) {
			$pppoe = false;
			if (isset($mt['config']['system interface']['wan2']['mode'])) {	
				if ($mt['config']['system interface']['wan2']['mode']=='pppoe') {		
					$pppoe=true;
				}
			}
			if ($pppoe==true) { 
				$passwd = $mt['config']['system interface']['wan2']['password'];
				$passwd = (strpos($passwd, 'ENC') !== false) ? 'ENCODED' : $passwd;
				$s.="/interface pppoe-client add name=pppoe-user2 user=".$mt['config']['system interface']['wan2']['username']." password=".$passwd." interface=wan1 service-name=".$mt['config']['system interface']['wan2']['alias']." disabled=no".$lf;
			} else {		
				$s .="/ip address add address=".str_replace(" 255.255.255.0","",$mt['config']['system interface']['wan2']['ip'])."/24 interface=wan2".$lf;	
			}
			if (strtolower($mt['config']['system interface']['wan2']['alias'])=='internet') { $internet_wan = "wan2"; }
		}

		// iterate through vap-switch interfaces
		$i=4;
		foreach ($mt['config']['system interface'] as $key=>$value) {
			if ($value['type']=='vap-switch') {
				$s .="/interface set ".$i." name=".$key."".$lf;
				$s .="/ip address add address=".str_replace(" 255.255.255.0","",$value['ip'])."/24 interface=".$key."".$lf;
				$i++;
			}	
		}

		// srcnat for internet connection
		$addr = explode('.',$mt['config']['system interface']['lan']['ip']);
		$s .= "/ip firewall nat add chain=srcnat action=masquerade src-address=".$addr[0].".".$addr[1].".".$addr[2].".0/24 out-interface=".$internet_wan."".$lf;

		// dns server
		$dns = "1.1.1.1";
		if (isset($mt['config']['system dns'])) {
			$ss = (isset($mt['config']['system dns']['secondary'])) ? ",".$mt['config']['system dns']['secondary'] : "";
			$dns = $mt['config']['system dns']['primary'].$ss;
			$s.="/ip dns set servers=".$dns."".$lf;
		}


		// dyn ddns client
		if ((isset($mt['config']['system ddns'][1]['ddns-server'])) && (isset($mt['config']['system ddns'][2]['ddns-server']))) {
			// $s.="/tool dns-update dns-server=".$mt['config']['system ddns'][0]['ddns-server']." name=".$mt['config']['system ddns'][0]['ddns-domain'];
			// http://{username}:{password}@members.dyndns.org/nic/update?hostname={yourhostname}&myip={ipaddress}&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG
			
			$s.="".$lf;
			
			$passwd = $mt['config']['system ddns'][2]['ddns-password'];
			$passwd = (strpos($passwd, 'ENC') !== false) ? 'ENCODED' : $passwd;
			
			$s .= "/system script".$lf;
			$s .= ":local username \"".$mt['config']['system ddns'][2]['ddns-username']."\"".$lf;
			$s .= ":local password \"".$passwd."\"".$lf;
			$s .= ":local host \"".$mt['config']['system ddns'][1]['ddns-domain']."\"".$lf;
			$s .= ":global previousIP".$lf;
			$s .= ":log info (\"Update DynDNS DNS: username = \$username\")".$lf;
			$s .= ":log info (\"Update DynDNS DNS: hostname = \$host\")".$lf;
			$s .= ":log info (\"Update DynDNS DNS: previousIP = \$previousIP\")".$lf;
			$s .= "/tool fetch mode=http address=\"checkip.dyndns.org\" src-path=\"/\" dst-path=\"/dyndns.checkip.html\"".$lf;
			$s .= ":delay 2".$lf;
			$s .= ":local result [/file get dyndns.checkip.html contents]".$lf;
			$s .= ":log info \"dyndns result = \$result\"".$lf;
			$s .= ":local resultLen [:len \$result]".$lf;
			$s .= ":local startLoc [:find \$result \": \" -1]".$lf;
			$s .= ":set startLoc (\$startLoc + 2)".$lf;
			$s .= ":local endLoc [:find \$result \"</body>\" -1]".$lf;
			$s .= ":local currentIP [pick \$result \$startLoc \$endLoc]".$lf;
			$s .= ":log info \"DynDNS DNS: currentIP = \$currentIP\"".$lf;
			$s .= ":if (\$currentIP != \$previousIP) do={".$lf;
			$s .= ":log info \"DynDNS: Current IP \$currentIP is not equal to previous IP, update needed\"".$lf;
			$s .= ":set previousIP \$currentIP".$lf;
			$s .= ":local url \"http://\$username:\$password@members.dyndns.org/nic/update?myip=\$currentIP&hostname=\$host&wildcard=NOCHG&mx=NOCHG&backmx=NOCHG\"".$lf;
			$s .= ":log info \"DynDNS DNS: Sending update for \$host\"".$lf;
			$s .= "/tool fetch url=\$url mode=http dst-path=(\"DynDNS_ddns_update.txt\")".$lf;
			$s .= ":log info \"DynDNS DNS: Host \$host updated on DynDNS with IP \$currentIP\"".$lf;
			$s .= ":delay 2".$lf;
			$s .= ":local result [/file get \"DynDNS_ddns_update.txt\" contents]".$lf;
			$s .= ":log info \"Update Result = \$result\"".$lf;
			$s .= "} else={".$lf;
			$s .= ":log info \"DynDNS: update not needed \"".$lf;
			$s .= "}".$lf;

		}

		// dhcp
		if (isset($mt['config']['ip-range'][1]['start-ip'])) {	
			$s.="".$lf;

			$addr = explode('.',$mt['config']['ip-range'][1]['start-ip']);
			$s .= "/ip pool add name=DHCP-POOL ranges=".$mt['config']['ip-range'][1]['start-ip']."-".$addr[0].".".$addr[1].".".$addr[2].".254".$lf;
			$s .= "/ip dhcp-server enable 1".$lf;
			$s .= "/ip dhcp-server add interface=lan  addree-pool=DHCP-POOL".$lf;	
			$dns = $mt['config']['reserved-address']['dns-server1'];
			if (isset($mt['config']['reserved-address']['dns-server2'])) {
				$dns .= ",".$mt['config']['reserved-address']['dns-server2'];
			}
			$s .= "/ip dhcp-server network add address=".$addr[0].".".$addr[1].".".$addr[2].".0/24 gateway=".$mt['config']['system interface']['lan']['ip']." dns-server = ".$dns." comment=\"DHCP-POOL\"".$lf;
		}


		// default firewall policy
		$s.="".$lf;
		$s .="/ip firewall filter add action=accept chain=input comment=\"accept established,related,untracked\" connection-state=established,related,untracked".$lf;
		$s .="/ip firewall filter add action=drop chain=input comment=\"drop invalid\" connection-state=invalid".$lf;
		$s .="/ip firewall filter add action=accept chain=input comment=\"accept ICMP\" protocol=icmp".$lf;
		$s .="/ip firewall filter add action=accept chain=input comment=\"accept to local loopback (for CAPsMAN)\" dst-address=127.0.0.1".$lf;
		$s .="/ip firewall filter add action=accept chain=forward comment=\"accept in ipsec policy\" ipsec-policy=in,ipsec".$lf;
		$s .="/ip firewall filter add action=accept chain=forward comment=\"accept out ipsec policy\" ipsec-policy=out,ipsec".$lf;
		$s .="/ip firewall filter add action=fasttrack-connection chain=forward comment=\"fasttrack\" connection-state=established,related".$lf;
		$s .="/ip firewall filter add action=accept chain=forward comment=\"accept established,related, untracked\" connection-state=established,related,untracked".$lf;
		$s .="/ip firewall filter add action=drop chain=forward comment=\"drop invalid\" connection-state=invalid".$lf;
		$s .="/ip firewall filter add action=drop chain=forward comment=\"drop all from WAN not DSTNATed\" connection-nat-state=!dstnat connection-state=new in-interface=".$internet_wan."".$lf;
		// $s .="/ip firewall nat add action=masquerade chain=srcnat comment=\"masquerade\" ipsec-policy=out,none out-interface=".$internet_wan.$lf;

		$s.="".$lf;
		// firewall
		if (isset($mt['config']['firewall policy'])) {	
			foreach ($mt['config']['firewall policy'] as $row) {		
				$srcintf = ($row['srcintf']!='any') ? " in-interface=".str_replace(" ","",$row['srcintf']) : "";		
				$dstintf = ($row['dstintf']!='any') ? " out-interface=".str_replace(" ","",$row['dstintf']) : "";	
				$action = (isset($row['action'])) ? " action=".$row['action'] : " action=drop";
				$srcaddr = $this->get_address($mt,str_replace(" ","",$row['srcaddr']),'src');
				$dstaddr = $this->get_address($mt,str_replace(" ","",$row['dstaddr']),'dst');		
			
				$comment = " comment=\"".$row['srcaddr']."->".$row['dstaddr']."\"";
				
				$chain = "forward";
				if ((!empty($srcaddr)) && (!empty($dstaddr))) {
					$chain = "forward";	
				}
				if ((!empty($srcaddr)) && (empty($dstaddr))) {
					$chain = "input";	
				}
				if ((empty($srcaddr)) && (!empty($dstaddr))) {
					$chain = "output";	
				}
						
				$s.="/ip firewall filter add chain=".$chain." protocol=tcp".$srcintf.$dstintf.$action.$srcaddr.$dstaddr.$comment."".$lf;		
			}
		}

		$s.="".$lf;
		// ipsec server
		if (isset($mt['config']['vpn ipsec phase1-interface']['IPSec']['interface'])) {	
			$s .="/ppp profile add name=ipsec_vpn local-address=".$mt['config']['vpn ipsec phase1-interface']['IPSec']['ipv4-start-ip']." dns-server=".$mt['config']['vpn ipsec phase1-interface']['IPSec']['ipv4-dns-server1']."".$lf;
			$s .="/interface l2tp-server server set enabled=yes default-profile=ipsec_vpn authentication=mschap1,mschap2".$lf;	
			$s .="/ip ipsec peer add exchange-mode=main passive=yes name=l2tpserver".$lf;
			$passwd = $mt['config']['vpn ipsec phase1-interface']['IPSec']['psksecret'];
			$passwd = (strpos($passwd, 'ENC') !== false) ? 'ENCODED' : $passwd;
			$s .="/ip ipsec identity add generate-policy=port-override auth-method=pre-shared-key secret=".$passwd." peer=l2tpserver".$lf;
			$s .="/ip ipsec proposal set default auth-algorithms=sha1 enc-algorithms=3des pfs-group=modp1024".$lf;
			
			$addr = explode('.',$mt['config']['vpn ipsec phase1-interface']['IPSec']['ipv4-start-ip']);
			$addr_num = (int)$addr[3];
			
			// iterration user-each
			foreach ($mt['config']['user local'] as $key=>$value) {	
				if (isset($value['passwd-time'])) {
					$addr_num++;
					$passwd = $value['passwd'];
					$passwd = (strpos($passwd, 'ENC') !== false) ? 'ENCODED' : $passwd;
					$s .="/ppp secret add name=".$key." password=".$passwd." service=l2tp profile=ipsec_vpn remote-address=".$addr[0].".".$addr[1].".".$addr[2].".".$addr_num."".$lf;
				}
			}
			
			$s .="/ip firewall filter add chain=input action=accept protocol=udp port=1701,500,4500 in-interface=".$mt['config']['vpn ipsec phase1-interface']['IPSec']['interface']."".$lf;
			$s .="/ip firewall filter add chain=input action=accept protocol=ipsec-esp in-interface=".$mt['config']['vpn ipsec phase1-interface']['IPSec']['interface']."".$lf;
		}

		$s.="".$lf;
		// address lists
		// for simple IP address lists only
		if (isset($mt['config']['system external-resource'])) {	
			foreach ($mt['config']['system external-resource'] as $key=>$value) {	
				if ($value['type']=='address') {
					$arr = explode('/',$value['resource']);
					$path = "";
					for ($i=3;$i<count($arr);$i++) {
						$path .= "/".$arr[$i];
					}
					$s .="/tool fetch address=".$arr[2]." host=".$arr[2]." mode=".explode(':',$arr[0])[0]." src-path=".ltrim($path,'/')." dst-path=".$key.".txt".$lf.$lf;
					
					$s .=":if ( [/file get [/file find name=".$key.".txt] size] > 0 ) do={".$lf;
					$s .="/ip firewall address-list remove [/ip firewall address-list find list=".$key."]".$lf;
					$s .=":global content [/file get [/file find name=".$key.".txt] contents] ;".$lf;
					$s .=":global contentLen [ :len \$content ] ;".$lf;

					$s .=":global lineEnd 0;".$lf;
					$s .=":global line \"\";".$lf;
					$s .=":global lastEnd 0;".$lf;

					$s .=":do {".$lf;
					$s .="	:set lineEnd [:find \$content \"\n\" \$lastEnd ] ;".$lf;
					$s .="	:set line [:pick \$content \$lastEnd \$lineEnd] ;".$lf;
					$s .="	:set lastEnd ( \$lineEnd + 1 ) ;".$lf;

					$s .="	:if ( [:pick \$line 0 1] != \"#\" ) do={".$lf;
					$s .="	:local entry [:pick \$line 0 (\$lineEnd -1) ]".$lf;
					$s .="	:if ( [:len \$entry ] > 0 ) do={".$lf;
					$s .="		/ip firewall address-list add list=".$key." address=\$entry".$lf;
					$s .="	}".$lf;
					$s .="}".$lf;
					$s .="} while (\$lineEnd < \$contentLen)".$lf;
					$s .="}".$lf.$lf; 
					
					$s .="/ip firewall filter add action=drop chain=input src-address-list=".$key.$lf;
				}
			}
		}

		return $s;

	}

}



?>