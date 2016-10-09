#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

"""

Requirements:

    Python 2.7

        pip install requests future ndg-httpsclient dnspython tld

    Python 3

        pip requests dnspython tld

"""
from builtins import str

import dns.exception
import dns.resolver
import logging
import time
import json
import sys
import os

import hover
import requests
from tld import get_tld
if sys.version_info.major == 2:
    from future import standard_library
    standard_library.install_aliases()

if not hasattr(logging, 'TRACE'):
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, "TRACE")

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    except AttributeError:
        # see https://github.com/certbot/certbot/issues/1883
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

if os.path.exists(sys.argv[0]+".log_conf.json"):
    import logging.config
    if __name__ == '__main__':
        logging.config.dictConfig({"version": 1, "disable_existing_loggers": False})
    with open(sys.argv[0]+".log_conf.json") as config:
        logging.config.dictConfig(json.load(config))
    logger = logging.getLogger(__name__)
else:
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG if 'HOVER_DEBUG' in os.environ else logging.INFO)

try:
    HOVER_USERNAME = os.environ['HOVER_USERNAME'],
    HOVER_PASSWORD = os.environ['HOVER_PASSWORD'],
except KeyError:
    # hover session token is normally cached so this is just a warning
    logger.warning(" + Unable to locate hover credentials in environment!")

try:
    # ns1.hover.com ns2.hover.com
    dns_servers = os.environ['HOVER_DNS_SERVERS'] if 'HOVER_DNS_SERVERS' in os.environ else '216.40.47.26 64.98.148.13'
    dns_servers = dns_servers.split()
except KeyError:
    dns_servers = False

storage_path = None

if 'HOVER_STORAGE' in os.environ:
    storage_path = os.environ['HOVER_STORAGE']


def _has_dns_propagated(name, token):
    txt_records = []
    logger.debug("Looking for TXT record with the value: '%s'" % token)
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')
        for rdata in dns_response:
            for txt_record in rdata.strings:
                logger.debug("Found TXT record with the value: '%s'" % txt_record)
                # see https://groups.google.com/d/topic/dnspython-users/bKi_bxL48rI/discussion
                if hasattr(txt_record, 'decode'):
                    txt_record = txt_record.decode("utf-8")
                txt_records.append(txt_record)
    except dns.exception.DNSException as error:
        return False

    for txt_record in txt_records:
        if txt_record == token:
            return True

    return False


def create_txt_record(args):
    domain, token = args[0], args[2]
    verify_fqdn = "{0}.{1}".format('_acme-challenge', domain)

    logger.debug("TXT record created for {0} with {1}".format(verify_fqdn, token))

    api = hover.Hover(storage_path=storage_path)
    try:
        quoted_token = "' %s'" % token if token[0] == "-" else token
        api.command(["--add", verify_fqdn, "TXT", quoted_token])
    except hover.HoverError as e:
        logger.error("Error: " + e.message)
        sys.exit(1)

    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 5s...")
    time.sleep(5)

    while not _has_dns_propagated(verify_fqdn, token):
        logger.info(" + DNS not propagated, waiting 10s...")
        time.sleep(10)


def delete_txt_record(args):
    domain = args[0]
    delete_fqdn = "{0}.{1}".format('_acme-challenge', domain)

    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    api = hover.Hover(storage_path=storage_path)
    try:
        result = api.command(["--dns-list", "--filter", delete_fqdn])
    except (hover.HoverException, hover.HoverError) as e:
        logger.error("Error: " + e.message)
        sys.exit(1)

    if result is None or result is False or 'domains' not in result:
        logger.error("Error, expecting hover util output: %s" % repr(result)[:200])
        sys.exit(1)

    if len(result['domains']) < 1:
        logger.warn("Expected DNS TXT for %s record not found" % delete_fqdn)

    for dns_rec in result['domains']:
        if dns_rec[2] == "TXT":
            result = api.command(["--delete", dns_rec[0]])
        else:
            logger.warn("Unexpected DNS record: %s" % " ".join(dns_rec[1:]))

    logger.debug(" + deleting TXT record name: {0}".format(delete_fqdn))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    return


def main(argv):
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
    }
    logger.info(" + Hover hook executing: {0}".format(argv[0]))
    logger.info(" + Hover hook executing with: {0}".format(" ".join(argv[1:])))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
