
alternc nginx ssl module using ACME.SH
======================================

This is an extension for AlternC that provides an nginx proxy configuration
(from https to http) and automatically creates an ACME TLS certificate for each FQDN hosted by AlternC.

the acme.sh ACME client is used, as configured. So you MUST configure it ;) 
by choosing your ACME provider and registering there

this package installs acme.sh in /usr/local/sbin/ with a default homedir in /etc/acme.sh
via a file in /etc/environment.d/ 

to create an acme account, log out and log in (to get the ENV var) then use : 

acme.sh --register-account  --server <zerossl|letsencrypt> \
    [ --eab-kid <your-provider-kid> --eab-hmac-key <your-provider-hmac> ] 
acme.sh --set-default-ca  --server <zerossl|letsencrypt>


