#!/usr/bin/make -f
# ----------------------------------------------------------------------
# AlternC - Web Hosting System
# Copyright (C) 2000-2013 by the AlternC Development Team.
# https://alternc.org/
# ----------------------------------------------------------------------
# LICENSE
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License (GPL)
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# To read the license please visit http://www.gnu.org/copyleft/gpl.html
# ----------------------------------------------------------------------
# Purpose of file: Global Makefile
# ----------------------------------------------------------------------

build:

install:
	install -m 0755 -o root -g root update_nginx-ssl.sh $(DESTDIR)/usr/lib/alternc/
	install -m 0644 -o root -g root nginx.conf $(DESTDIR)/etc/alternc/templates/nginx/
	install -m 0644 -o root -g root nginx-template.conf $(DESTDIR)/etc/alternc/templates/nginx/
	install -m 0755 -o root -g root alternc-nginx-ssl-install $(DESTDIR)/usr/lib/alternc/install.d/
	install -m 0644 -o root -g root nginx-ssl-letsencrypt.conf $(DESTDIR)/etc/apache2/conf-enabled/

