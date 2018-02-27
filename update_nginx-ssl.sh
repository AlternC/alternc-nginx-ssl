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
 */ 

$lock="/run/update_nginx-ssl.lock";
if (is_file($lock) && is_dir("/proc/".intval(file_get_contents($lock)))) {
    echo "Nginx-ssl locked\n";
    exit(0);
}
file_put_contents($lock,getmypid());


putenv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
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
        if ($templates) $templates.=",";
        $templates="'".substr($c,0,-5)."'";
    }
}
closedir($d);

// open a connection to the DB, get variables:
// I will use $L_PUBLIC_IP too
require_once("/usr/share/alternc/panel/class/config_nochk.php");

openlog("[AlternC Nginx SSL]",null,LOG_USER);

// Search for anything we are hosting locally :
$nginxdir="/etc/nginx/sites-enabled";
$letsencryptdir="/etc/letsencrypt/live";
$reload=false;
$db->query("SELECT domaine,sub FROM sub_domaines WHERE type IN (".$templates.");");
while ($db->next_record()) {
    if ($db->Record["sub"])
        $fqdn=$db->Record["sub"].".".$db->Record["domaine"];
    else
        $fqdn=$db->Record["domaine"];
    // Check the DNS for this domain.
    $out=array();
    exec("dig +short A ".escapeshellarg($fqdn),$out);
    $found=false;
    foreach($out as $line) {
        if (trim($line)==$L_PUBLIC_IP) {
            $found=true;
            break;
        }
    }
    if (!$found) { // MY IP address is not in the DNS for this FQDN...
        continue; // Skip this host entirely... TODO : delete files in /etc/letsencrypt/live/ archive/ and renewal/
    }
    // This FQDN is in our official list. (we will delete nginx vhosts NOT in this list at the end)
    $fqdnlist[]=$fqdn;
    // cases :
    // - nginx OK + letsencrypt OK => do nothing
    // - nginx NOK + letsencrypt OK => configure the vhost

    // - nginx NOK + letsencrypt NOK => get a letsencrypt cert
    if (!is_dir($letsencryptdir."/live/".$fqdn) ||
    !is_link($letsencryptdir."/live/".$fqdn."/fullchain.pem") ||
    !is_link($letsencryptdir."/live/".$fqdn."/privkey.pem")) {
        // letsencrypt not ready, do it :) (unless we are throttled, in that case, quit...)
        // TODO : handle throttle in Letsencrypt : 1. no more than 10 certs per hour, 2. no more than 5 failure per hour
        // 3. skip domain for which we had 2 failures in the previous day.
        // 4. skip domain for which we had 1 failure in the previous hour. (allow to prioritize other FQDNs)
        $out=array(); $ret=-1;
        exec("/usr/bin/letsencrypt certonly --webroot --agree-tos -w /var/www/letsencrypt/ --email root@".trim(file_get_contents("/etc/mailname"))." --expand -d ".escapeshellarg($fqdn),$out,$ret);
        if ($ret!=0) {
            // Log the failure skip it...
            syslog("Can't get a certificate for $fqdn, letsencrypt logged this:");
            foreach($out as $line) if (trim($line)) syslog(trim($line));
            // TODO : add it to our memory (for the throttling)
        }
    } else {
        // Cert is OK, let's check nginx conf :
        if (!is_file($nginxdir."/".$fqdn.".alternc.conf")) {
            file_put_contents(
                $nginxdir."/".$fqdn.".alternc.conf",
                str_replace("%%FQDN%%",$fqdn,file_get_contents("/etc/alternc/templates/nginx/nginx-template.conf"))
            );
            $reload=true;
        }
    }
}


// Remove old or expired configuration files from Nginx :
$d=opendir($nginxdir);
if (!$d) {
    echo "Can't open $nginxdir\n";
    exit(1);
    @unlink($lock);
}
while (($c=readdir($d))!==false) {
    if (is_file($nginxdir."/".$c) && substr($c,-13)==".alternc.conf") {
        if (!in_array(substr($c,0,-13),$fqdnlist)) {
            $reload=true;
            unlink($nginxdir."/".$c);
        }
    }
}
closedir($d);

if ($reload) {
    syslog("Reloading Nginx...");
    exec("service nginx reload");
}

@unlink($lock);

