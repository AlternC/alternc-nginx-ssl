#!/usr/bin/php
<?php

/*
----------------------------------------------------------------------
 AlternC - Web Hosting System
 Copyright (C) 2000-2012 by the AlternC Development Team.
 https://alternc.org/
 ----------------------------------------------------------------------
 LICENSE

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License (GPL)
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 To read the license please visit http://www.gnu.org/copyleft/gpl.html
 ----------------------------------------------------------------------
 Purpose of file: Update nginx conf + letsencrypt certs
 ----------------------------------------------------------------------
 */
 
/**
 * update the NGINX configuration for each VHOST we are currently hosting on the server
 * if necessary, generate or update a letsencrypt certificate.
 * if necessary, reload nginx.
 * throttle the letsencrypt requests, thanks to a cache file in /var/cache/nginx-ssl/requests.json
 * has a blacklist of FQDN & domains to ignore (because we have too many or they are provoking errors, like too long fqdn on jessie's certbot)
 * the blacklist is a one-line-per-domaine file in /etc/alternc/nginx-ssl.blacklist.txt
 */ 

// ------------------------------------------------------------
if (getmyuid()!=0) {
    echo "Fatal: must be launched as root !\n";
    exit(1);
}
$lock="/run/update_nginx-ssl.lock";
if (is_file($lock) && is_dir("/proc/".intval(file_get_contents($lock)))) {
    echo "Nginx-ssl locked\n";
    exit(0);
}
file_put_contents($lock,getmypid());

// ------------------------------------------------------------
// This is the list of alternc templates for which we DO have a vhost for Apache :
$templatedir="/etc/alternc/templates/apache2";
$d=opendir($templatedir);
if (!$d) {
    echo "Can't open /etc/alternc/templates/apache2\n";
    @unlink($lock);
    exit(1);
}
$templates="";
while (($c=readdir($d))!==false) {
    if (is_file($templatedir."/".$c) && substr($c,-5)==".conf") {
        $c=preg_replace('#-(http|https|both)\.conf$#','.conf',$c);
        if ($templates) $templates.=",";
        $templates.="'".substr($c,0,-5)."'";
    }
}
closedir($d);

// fqdn/domains blacklist
$blacklist=@explode("\n",@file_get_contents("/etc/alternc/nginx-ssl.blacklist.txt"));
if (!is_array($blacklist)) $blacklist=array();

// ------------------------------------------------------------
// open a connection to the DB, get variables:
// I will use $L_PUBLIC_IP too
require_once("/usr/share/alternc/panel/class/config_nochk.php");
putenv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
openlog("[AlternC Nginx SSL]",null,LOG_USER);

// All my ips : 
$myips=array($L_PUBLIC_IP);
exec('ip address show|grep \'inet \'|sed -e \'s#^.*inet \([^/]*\).*#\1#\'|grep -v 127.0.0.1',$myips);
// ' );

// ------------------------------------------------------------
// Throttling functions : 
$cachedir="/var/cache/nginx-ssl";
if (is_file($cachedir."/status.json")) {
    $status=json_decode(file_get_contents($cachedir."/status.json"),true);
} else {
    $status=array( "failures"=>array(), "requests"=>array(), "lastrenew"=>0, "uninstall" => array() );
    @mkdir($cachedir);
}
// cleanup of entries older than 2 days : 
$now=time();
foreach($status["failures"] as $k=>$v) {
    if ($v[1]<($now-86400*2)) unset($status["failures"][$k]);
}
foreach($status["requests"] as $k=>$v) {
    if ($v[1]<($now-86400*2)) unset($status["requests"][$k]);
}
file_put_contents($cachedir."/status.json",json_encode($status));

// log any successful Letsencrypt request :
function letsencrypt_request($fqdn) {
    global $status;
    $status["requests"][]=array($fqdn,time());
}
// log any failure in Letsencrypt request :
function letsencrypt_failure($fqdn) {
    global $status;
    $status["failures"][]=array($fqdn,time());
}


// ------------------------------------------------------------
// tell whether we can do a Letsencrypt Request for this FQDN now
// don't do a request if we had 1 failure in the last hour or 3 failures in the last day FOR THIS FQDN
// or we had more than 5 failures in the last hour or 10 requests in the last hour 
function letsencrypt_allowed($fqdn) {
    global $status;
    $fqdnperday=0; $fqdnperhour=0;
    $failureperhour=0; $requestperhour=0;
    $now=time();
    foreach($status["failures"] as $k=>$v) {
        if ($fqdn==$v[0] && $v[1]>($now-3600)) $fqdnperhour++;
        if ($fqdn==$v[0] && $v[1]>($now-86400)) $fqdnperday++;
        if ($v[1]>($now-3600)) $failureperhour++;
    }
    foreach($status["requests"] as $k=>$v) {
        if ($v[1]>($now-3600)) $requestperhour++;
    }
    if ($requestperhour>=100 || $fqdnperhour>=10 || $fqdnperday>=30 || $failureperhour>=20) {
        return false;
    }
    return true;
}


// ------------------------------------------------------------
// function to see if it's necessary, and do a cert renewal: 
function try_renew($fqdn) {
    global $letsencryptdir,$reload,$myips;
    if (!is_link($letsencryptdir."/live/".$fqdn."/cert.pem")) {
        syslog(LOG_ERR,"Can't find cert.pem for renewal of $fqdn, weird");
        return false;
    }
    exec("openssl x509 -in ".escapeshellarg($letsencryptdir."/live/".$fqdn."/cert.pem")." -noout -enddate",$out,$ret);
    if ($ret!=0) {
        syslog(LOG_ERR,"invalid cert.pem for $fqdn");
        return false;
    }
    // Apr 14 23:00:53 2018 GMT
    if (count($out) && preg_match("#notAfter=(.*)#",$out[0],$mat)) {
        $expires = DateTime::createFromFormat("M j H:i:s Y e",$mat[1]);
        if (!is_object($expires)) {
            syslog(LOG_ERR,"invalid cert.pem for $fqdn, date can't be parsed: ".$mat[1]);
            return false;      
        }
        if ($expires->format("U")<(time()+86400*30)) {
            // is expired, renewing...
            $out=array();
            exec("dig +short A ".escapeshellarg($fqdn),$out);
            $found=false;
            foreach($out as $line) {
                if (in_array( trim($line), $myips)) {
                    $found=true;
                    break;
                }
            }
            if (!$found) { // MY IP address is not in the DNS for this FQDN...
                syslog(LOG_ERR,"we should renew $fqdn, but it is not pointing to us in the DNS. skipping");
                return false;
            }
            syslog(LOG_INFO,"Cert for $fqdn will expire in less than 30 days, renewing...");
            $out=array();
            sleep(1); // prevent to hit the global throttle of 10hits/sec on LE servers
            exec("/usr/bin/letsencrypt certonly --webroot -w /var/www/letsencrypt/ --expand -d ".escapeshellarg($fqdn)." 2>&1",$out,$ret);
            if ($ret!=0) {
                // Log the failure skip it...
                syslog(LOG_ERR,"Can't get a certificate renewal for $fqdn, letsencrypt logged this:");
                foreach($out as $line) if (trim($line)) syslog(LOG_ERR,trim($line));
                letsencrypt_failure($fqdn);
            } else {
                syslog(LOG_INFO,"got a renewed certificate for $fqdn");
                $reload=true;
                // letsencrypt_request($fqdn); // RENEWAL are not counting in the throttling ;) 
            }
        }
    }
}


// ------------------------------------------------------------
// Search for anything we are hosting locally :
$nginxdir="/etc/nginx/sites-enabled";
$letsencryptdir="/etc/letsencrypt";
$reload=false;
$renew=false;

// try the renewals only on Mondays, every 4 hours between 8 am and 5 pm :) 
if (date("N")==1 && date("H")>7 && date("H")<17 && (!isset($status["lastrenew"]) || $status["lastrenew"]<(time()-14400))) {
    $renew=true;
}
$db->query("SELECT domaine,sub FROM sub_domaines WHERE type IN (".$templates.");");
$fqdnlist[]=$fqdn;
while ($db->next_record()) {

    $fqdn=$db->Record["sub"].(($db->Record["sub"])?".":"").$db->Record["domaine"];

    if (in_array($db->Record["domaine"],$blacklist) || in_array($fqdn,$blacklist)) {
        continue;
    }

	// Check the DNS for this fqdn. it should point to one of our IP addresses
    $out=array();
    exec("dig +short A ".escapeshellarg($fqdn),$out);
    $found=false;
    foreach($out as $line) {
        if (in_array( trim($line), $myips)) {
            $found=true;
            break;
        }
    }
    if (!$found) { // MY IP address is not in the DNS for this FQDN...
        continue; 
    }

    // cases :
    // - nginx OK + letsencrypt OK => do nothing

    // - nginx NOK + letsencrypt NOK => get a letsencrypt cert
    if (!is_dir($letsencryptdir."/live/".$fqdn) ||
    !is_link($letsencryptdir."/live/".$fqdn."/fullchain.pem") ||
    !is_link($letsencryptdir."/live/".$fqdn."/privkey.pem")) {
        // letsencrypt not ready for this fqdn, do it :) (unless we are throttled, in that case, quit...)        
        if (!letsencrypt_allowed($fqdn)) {
            continue; // Skip this host entirely
        }
        
        $out=array(); $ret=-1;
        sleep(1); // prevent to hit the global throttle of 10hits/sec on LE servers
        exec("/usr/bin/letsencrypt certonly --webroot --agree-tos -w /var/www/letsencrypt/ --email root@".trim(file_get_contents("/etc/mailname"))." --expand -d ".escapeshellarg($fqdn)." 2>&1",$out,$ret);
        if ($ret!=0) {
            // Log the failure skip it...
            syslog(LOG_ERR,"Can't get a certificate for $fqdn, letsencrypt logged this:");
            foreach($out as $line) if (trim($line)) syslog(LOG_ERR,trim($line));
            letsencrypt_failure($fqdn);
        } else {
            syslog(LOG_INFO,"got a new certificate for $fqdn");
            letsencrypt_request($fqdn);
        } 
    }
    
    // - nginx NOK + letsencrypt OK => configure the vhost
    if (is_dir($letsencryptdir."/live/".$fqdn) && is_link($letsencryptdir."/live/".$fqdn."/fullchain.pem") && is_link($letsencryptdir."/live/".$fqdn."/privkey.pem")) {
        if (!is_file($nginxdir."/".$fqdn.".alternc.conf") && !is_file($nginxdir."/".$fqdn.".manual.conf")) { // if you define a vhost with .manual.conf, we ignore AlternC's one (allow for a Varnish conf or others
            file_put_contents(
                $nginxdir."/".$fqdn.".alternc.conf",
                str_replace("%%FQDN%%",$fqdn,file_get_contents("/etc/alternc/templates/nginx/nginx-template.conf"))
            );
            syslog(LOG_INFO,"put nginx conf for $fqdn");
            $reload=true;
        }
        // If a cert exists AND we want to test its renewal, let's test its date:
        if ($renew) try_renew($fqdn);
    }
}

// ------------------------------------------------------------
// Remove old or expired configuration files from Nginx :
// We don't remove them at once, we wait for a FQDN to be pointing somewhere else for at least 2 DAYS
// so that we don't delete certificates at once.

$d=opendir($nginxdir);
if (!$d) {
    echo "Can't open $nginxdir\n";
    exit(1);
    @unlink($lock);
}
// search for the bad ones NOW 
$badlist=array();
while (($c=readdir($d))!==false) {
    if (is_file($nginxdir."/".$c) && substr($c,-13)==".alternc.conf") {
        if (!in_array(substr($c,0,-13),$fqdnlist)) {
            $badlist[]=substr($c,0,-13);
        }
    }
}
closedir($d);
// compare that with the status list (both ways)
if (array_key_exists("uninstall", $status)) {
    foreach($status["uninstall"] as $fqdn=>$ts) {
        if (!in_array($fqdn,$badlist)) {
            unset($status["uninstall"][$fqdn]);
        }
    }
    foreach($badlist as $fqdn) {
        if (!isset($status["uninstall"][$fqdn])) {
            $status["uninstall"][$fqdn]=time();
        } else {
            // not new, therefore may be here since >2day ?
            if ($status["uninstall"][$fqdn]<(time()-86400*2)) {
                unset($status["uninstall"][$fqdn]);
                // deleted since 2 days or more in a continuous way, let's delete cert & nginx conf
                $reload=true;
                unlink($nginxdir."/".$fqdn.".alternc.conf");
                exec("rm -rf ".escapeshellarg($letsencryptdir."/live/$fqdn")." ".escapeshellarg($letsencryptdir."/archive/$fqdn")." ".escapeshellarg($letsencryptdir."/renewal/".$fqdn.".conf"));
                syslog(LOG_INFO,"removed nginx conf & letsencrypt certificate for $fqdn");
            }
        }
    }
}


// we renewed the certs whose expiration date is < 30 days
if ($renew) $status["renewal"]=time();

// remember the cache (for throttling)
file_put_contents($cachedir."/status.json",json_encode($status));


if ($reload) {
    syslog(LOG_INFO,"Reloading Nginx...");
    exec("service nginx reload");
}

@unlink($lock);

