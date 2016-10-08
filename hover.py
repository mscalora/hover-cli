#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import string
import json
import time
import sys
import re
import os

import itertools

import logging

import requests

"""
Programatic and interactive Hover.com api classes

Requirements:

    python 2.7 or later, python 3
    requests (e.g. pip install requests)

HoverAPI - Wrapper class for Hover registrar REST API

    Highlights:

        Auth
        Lowlevel REST requests
        REST Resource url templates

    Example:

        >>> import hover
        >>> api = hover.HoverAPI()
        >>> api.login('example_account', 'secret')
        True

        >>> resp = api.call(hover.HoverAPI.methods["read"], hover.HoverAPI.apis["all_domains"])
        >>> print(str(resp)[:100] + "...")
        {u'domains': [{u'status': u'active', u'display_date': u'2027-07-27', u'locked': True, u'auto_renew':...

        >>> path = hover.HoverAPI.apis["dns_records_by_domain"].format(domain='dom9999000')
        >>> resp = api.call(hover.HoverAPI.methods["read"], path)
        >>> for e in resp['domains'][0]['entries']:
        ...   print(" ".join([k + '=' + str(e[k]) for k in ['id', 'name', 'type', 'content']]))
        ...
        id=dns99999001 name=@ type=A content=64.98.145.30
        id=dns99999002 name=* type=A content=64.98.145.30
        id=dns99999003 name=mail type=CNAME content=mail.hover.com.cust.hostedemail.com
        id=dns99999004 name=@ type=MX content=10 mx.hover.com.cust.hostedemail.com

Hover - Commandline utility for driving Hover registrar REST API

    Highlights:
        summary and detail list/report for domains, dns entries and settings with filtering
        dns entry creation, update (modify) & delete
        human readable text and machine readable json output
        can be used from command line or consumed as modle for higher level api vs HoveAPI above

    Examples:

        Domain List
            $ hover.py
            Hover userid: example
            Hover password: secret
            Hover ID   Domain Name DNS Primary   DNS Secondary
            dom9999999 example.com ns2.hover.com ns1.hover.com


"""

if sys.version_info.major == 2:
    prompt_for_input = raw_input
    from StringIO import StringIO
else:
    prompt_for_input = input
    from io import StringIO


class HoverException(Exception):

    logger = logging.getLogger('HoverException')

    def __init__(self, response):
        self.body = response.json() if hasattr(response, 'json') else None
        self.succeeded = self.body["succeeded"] if self.body is not None and "succeeded" in self.body else None
        self.error = self.body["error"] if self.body is not None and "error" in self.body else None
        self.error_code = self.body["error_code"] if self.body is not None and "error_code" in self.body else None

        HoverException.logger.debug('Hover API Error ({error_code}) {error}'.format(error=self.error, error_code=self.error_code))

        pass


class HoverAPI(object):
    """hover api class with session caching
    """

    dns_types = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV"]

    methods = {
        "create": "post",
        "read": "get",
        "update": "put",
        "delete": "delete"
    }

    apis = {
        "all_settings": "settings",

        "all_domains": "domains",
        "domain": "domains/{domain_id}",

        "all_dns_records": "dns",
        "dns_record": "dns/{dns_id}",                   # PUT/update & DELETE/delete but no GET/read or POST/create
        "dns_records_by_domain": "domains/{domain}/dns"  # SLD domain name or Hover domain_id
    }

    logger = logging.getLogger('HoverAPI')

    def __init__(self, persist_cookies=True, storage_path="~"):
        """instantiate hover api session, used cached data if specified"""
        self.hover_cookies_path = None
        if persist_cookies:
            data_path = os.path.expanduser("~") if storage_path is None or storage_path == "~" else storage_path
            cookie_file_name = ".hover-api-cookies" if storage_path == "~" else "hover-api-storage"
            self.hover_cookies_path = os.path.join(data_path, cookie_file_name)
        self.cookies = {}
        if persist_cookies and os.path.exists(self.hover_cookies_path):
            with open(self.hover_cookies_path, 'r') as cookies_file:
                try:
                    self.cookies = json.load(cookies_file)
                except ValueError:
                    self.cookies = {}
        self.authed = None
        self.body = None
        HoverAPI.logger.info("api object initialized")

    def _update_cookies(self, response):
        """update cookie cache"""
        self.cookies.update(response.cookies)
        if self.hover_cookies_path is not None:
            with open(self.hover_cookies_path, 'w') as cookies_file:
                json.dump(self.cookies, cookies_file)

    def _check_success(self, r):
        """test specified response for success"""
        if r.content:
            self.body = r.json()
            if "succeeded" not in self.body or self.body["succeeded"] is not True:
                if self.body["error_code"] == 'login':
                    self.authed = False
                return False
            self.authed = True
            return True
        else:
            return False

    def is_authed(self):
        """test if session is authenticated"""
        if self.authed is None:
            r = requests.get("https://www.hover.com/api/settings", cookies=self.cookies)
            return self._check_success(r)
        return self.authed

    def login(self, username=None, password=None, raise_on_error=False):
        """authenticate with hover server"""
        params = {
            "username": username if username is not None else os.getenv('HOVER_USERNAME', None),
            "password": password if password is not None else os.getenv('HOVER_PASSWORD', None)
        }
        if params['username'] is None or params['password'] is None:
            if raise_on_error:
                raise HoverException('missing credentials')
            else:
                return False
        HoverAPI.logger.info("login attempt for %s", params["username"])
        response = requests.post("https://www.hover.com/api/login", params=params, cookies=self.cookies)
        if not response.ok:
            if raise_on_error:
                raise HoverException(response)
            else:
                return False
        self._update_cookies(response)
        self.authed = self._check_success(response)
        return self.authed

    def logout(self):
        """deauthorize cached session"""
        HoverAPI.logger.info("logout")
        requests.get("https://www.hover.com/logout", cookies=self.cookies)
        self.purge_all()

    def purge_all(self):
        """purge cached data"""
        if self.hover_cookies_path is not None and os.path.exists(self.hover_cookies_path):
            os.remove(self.hover_cookies_path)
        self.authed = False
        self.body = None
        self.cookies = {}

    def call(self, method, resource, data=None, raise_on_error=False):
        """make hover api call"""
        HoverAPI.logger.info("REST request %s %s", method, resource)
        url = "https://www.hover.com/api/{0}".format(resource)
        self.logger.debug("%s - %s" % (method, url))
        r = requests.request(method, url, data=data, cookies=self.cookies)
        if r.ok:
            self._update_cookies(r)
        elif raise_on_error:
            raise HoverException(r)
        if self._check_success(r):
            return self.body
        if raise_on_error:
            raise HoverException(r)
        return False


class ListBuilder(object):
    list_def = None
    headers = []
    keys = []
    data = []
    col_len = []
    count = 0

    def __init__(self, list_def, detail=False, out=None, fmt='console', filter=None, max_line_len=None, for_domains=None):
        self.detail = detail
        self.list_def = list_def
        self.headers = list_def.headers
        self.keys = list_def.keys
        self.data = []
        self.count = 0
        self.out = sys.stdout if out is None else out
        self.format = fmt
        self.col_len = [len(h) for h in self.filtered(self.headers)]
        self.filter = filter
        self.for_domains = for_domains
        self.max_line_len = max_line_len
        self.filter_keys = None
        if self.filter is not None and not callable(self.filter) and ':' in self.filter:
            split_filter = self.filter.split(":", 1)
            self.filter_keys = [split_filter[0]]
            self.filter = split_filter[1] if len(split_filter) > 1 else None
        else:
            self.filter_keys = self.list_def.filters

    def get_in(self, value, subkey):
        if subkey == '':
            return value
        if subkey[0] == '[':
            parts = subkey.split(']', 1)
            index = parts[0].lstrip('[')
            value = value[index.strip("'") if index[0] == "'" else int(index)]
            return self.get_in(value, parts[1].strip())
        return value

    def _get_field(self, row, key):
        dot = key.find('.')
        sqr = key.find('[')
        if dot < 0 and sqr < 0:
            return row[key]
        if dot >= 0 and (sqr < 0 or dot < sqr):
            keys = key.split('.', 1)
            item = row[keys[0]]
            return self._get_field(item, keys[1])
        else:
            parts = key.split('[', 1)
            subkey = '['+parts[1]
            return self.get_in(row[parts[0]], subkey)

    def get_field(self, row, key):
        return self.resolve(self.list_def.key_to_index[key], self._get_field(row, key))

    def add_dict(self, line_data):
        if self.filter is not None:
            match = False
            if callable(self.filter):
                match = self.filter(line_data)
            else:
                for key in self.filter_keys:
                    val = self.get_field(line_data, key)
                    if val.find(self.filter) >= 0:
                        match = True
                        break
            if not match:
                return

        if self.for_domains is not None and len(self.for_domains) > 0:
            match = False
            for key in self.list_def.domains:
                val = self.get_field(line_data, key)
                for raw_item in self.for_domains:
                    item = raw_item.lower()
                    if item[0] == '.':
                        if val.endswith(item) or val == item[1:]:
                            match = True
                    elif item[0:2] == "*.":
                        if val.endswith(item[1:]) or val == item[2:]:
                            match = True
                    elif val == item:
                        match = True
                if match:
                    break

            if not match:
                return

        row_data = [self.get_field(line_data, key) for idx, key in enumerate(self.filtered(self.keys))]
        self.data.append(row_data)
        for i, field in enumerate(row_data):
            self.col_len[i] = max(self.col_len[i], len(str(field)))

    def resolve(self, idx, value):
        xform = self.list_def.xforms[idx]
        if xform is None:
            return value
        elif isinstance(xform, dict):
            # format to match output, see: http://goo.gl/FjKaO8
            val = format(value, "^")
            return xform[val] if val in xform else value
        elif hasattr(xform, '__call__'):
            return xform(value)
        return value

    def filtered(self, items):
        show_map = self.list_def.detail_map if self.detail else self.list_def.summary_map
        return [x[1] for x in zip(show_map, items) if x[0]]

    def output(self, line):
        if self.max_line_len is not None and len(line) >= self.max_line_len:
            print(line[:self.max_line_len - 0], file=self.out)
        else:
            print(line, file=self.out)

    def generate(self):
        if self.format == 'json' or self.format == 'json-flat':
            data = {
                "headers": self.filtered(self.headers),
                "domains": self.data
            }
            json.dump(data, self.out, indent=2)
        elif self.format == 'mapped' or self.format == 'json-mapped':
            key_index = 0 if self.list_def.row_index is None else self.filtered(self.keys).index(self.list_def.row_index)
            item_keys = self.filtered(self.headers)
            data = {row[key_index]: dict(zip(item_keys, row)) for row in self.data}
            json.dump(data, self.out, indent=2)
        else:
            if self.list_def.line_format is None:
                line_template = ""
                for items in zip(range(len(self.col_len)), self.list_def.aligns, self.col_len):
                    line_template += "{%s:%s%d} " % items
            else:
                line_template = self.list_def.line_format
            if self.list_def.header_format is None:
                header_format = line_template
            else:
                header_format = self.list_def.header_format
            self.output(header_format.format(*self.filtered(self.headers)).rstrip())
            for row_data in self.data:
                self.output(line_template.format(*row_data).rstrip())


class ListDef(object):
    TYPE_DIGIT = 1
    STR = 0
    INT = 1
    BOOL = 2
    EMAIL = 3
    URL = 4
    DOMAIN = 5

    ALIGN_DIGIT = 2
    LEFT = 10
    RIGHT = 20
    CENTER = 30

    GROUP_DIGIT = 3
    SUMMARY = 100
    HIDE = 200

    FILTER_DIGIT = 4
    FILTER = 1000

    SORT_DIGIT = 5
    ORDER = 10000

    ALIGN_CODES = {
        0: "",
        LEFT: "<",
        RIGHT: ">",
        CENTER: "^"
    }
    YES_NO = {"1": "yes", "0": "no"}

    def __init__(self, inits, row_index=None, data_set=None, title=None, line_format=None, header_format=None):
        self.headers = []
        self.keys = []
        self.xforms = []
        self.types = []
        self.aligns = []
        self.summary_map = []
        self.detail_map = []
        self.filters = []
        self.domains = []
        self.data_set = data_set
        self.line_format = line_format
        self.header_format = header_format
        self.title = title
        for item in inits:
            self.keys.append(item[0])
            self.headers.append(item[1])
            flags = item[2] if len(item) > 2 and item[2] is not None else 0
            self.types.append(iso_digit(flags, ListDef.TYPE_DIGIT))
            self.aligns.append(ListDef.align_code(flags))
            group = iso_digit(flags, ListDef.GROUP_DIGIT)
            self.summary_map.append(group == ListDef.SUMMARY)
            self.detail_map.append(group != ListDef.HIDE)
            if digit(flags, ListDef.FILTER_DIGIT) != 0:
                self.filters.append(item[0])
            if iso_digit(flags, ListDef.TYPE_DIGIT) == ListDef.DOMAIN:
                self.domains.append(item[0])
            self.xforms.append(item[3] if len(item) > 3 else None)
            self.row_index = row_index
        self.key_to_index = {key: idx for idx, key in enumerate(self.keys)}

    @staticmethod
    def align_code(flags):
        return ListDef.ALIGN_CODES[iso_digit(flags, ListDef.ALIGN_DIGIT)]

    def dump(self, file=sys.stdout):
        dims = [
                (self.headers, 'headers'),
                (self.keys, 'keys'),
                (self.xforms, 'xforms'),
                (self.types, 'types'),
                (self.aligns, 'aligns'),
                (self.summary_map, 'summary_map'),
                (self.detail_map, 'detail_map'),
        ]
        for dim in dims:
            print("{0:12.12}".format(dim[1]), " ".join(["{%d!s:10.10}" % x[0] for x in enumerate(dim[0])]).format(*dim[0]), file=file)


def digit(value, digit_number):
    return int(value / 10 ** (digit_number-1) % 10)


def iso_digit(value, digit_number):
    return int(value % 10 ** digit_number - value % 10 ** (digit_number-1))


class HoverError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class Hover(object):

    logger = logging.getLogger("Hover")

    domain_list_def = ListDef([
        ("id", "Hover ID", ListDef.SUMMARY),
        ("domain_name", "Domain Name", ListDef.SUMMARY + ListDef.DOMAIN + ListDef.FILTER),
        ("display_date", "Expiration"),
        ("registered_date", "Registered"),
        ("status", "Status"),
        ("locked", "Locked", ListDef.CENTER, ListDef.YES_NO),
        ("auto_renew", "Auto Renew", ListDef.CENTER, ListDef.YES_NO),
        ("num_emails", "Emails", ListDef.CENTER),
        ("whois_privacy", "Privacy", ListDef.STR + ListDef.CENTER, {"1": "yes", "0": "no", "unsupported": "n/a"}),
        ("nameservers[0]", "DNS Primary", ListDef.SUMMARY),
        ("nameservers[1]", "DNS Secondary", ListDef.SUMMARY),
    ], row_index="domain_name", title="Domain Info", data_set="domains")

    domain_admin_list_def = ListDef([
        ("id", "Hover ID"),
        ("domain_name", "Domain Name", ListDef.SUMMARY + ListDef.FILTER),
        ("Admin First Name", "contacts(admin)(first_name)"),
        ("Admin Last Name", "contacts(admin)(last_name)"),
        ("Admin Org Name", "contacts(admin)(org_name)"),
        ("Admin City", "contacts(admin)(city)"),
        ("Admin Zip", "contacts(admin)(zip)"),
        ("Admin Address1", "contacts(admin)(address1)"),
        ("Admin Address2", "contacts(admin)(address2)"),
        ("Admin Phone", "contacts(admin)(phone)"),
        ("Admin State", "contacts(admin)(state)"),
        ("Admin Country", "contacts(admin)(country)"),
        ("Admin Email", "contacts(admin)(email)"),
    ], row_index="domain_name", title="Domain Admin Info", data_set="domains")

    dns_list_def = ListDef([
        ("id", "DNS ID", ListDef.SUMMARY),
        ("fqdn", "Domain", ListDef.SUMMARY + ListDef.DOMAIN + ListDef.RIGHT + ListDef.FILTER),
        ("ttl", "TTL"),
        ("type", "Type", ListDef.SUMMARY),
        ("content", "Value", ListDef.SUMMARY),
        ("domain_id", "Domain ID", ListDef.HIDE),
        ("domain_name", "2LD", ListDef.HIDE),
        ("name", "Subdomain", ListDef.HIDE),
        ("is_default", "Default", ListDef.HIDE + ListDef.CENTER, {"1": "yes", "0": "no"}),
        ("can_revert", "Reverable", ListDef.HIDE + ListDef.CENTER, {"1": "yes", "0": "no"}),
    ], row_index='id', title="DNS Entries", data_set="dns")

    dns_backup_list_def = ListDef([
        ("id", "DNS ID", ListDef.SUMMARY),
        ("fqdn", "Domain", ListDef.SUMMARY + ListDef.DOMAIN + ListDef.FILTER),
        ("type", "Type", ListDef.SUMMARY),
        ("content", "Value", ListDef.SUMMARY),
    ], row_index='id', title="# DNS Entries", data_set="dns",
        line_format="\"${{hcmd}}\" \"${{hscript}}\" --add '{1}' {2} '{3}' # {0}",
        header_format="#!/usr/bin/env sh\nhcmd=python\nhscript=\"{0}\"".format(os.path.abspath(__file__)))

    settings_list_def = ListDef([
        ("rec_num", "Num", ListDef.HIDE),
        ("name", "Name", ListDef.SUMMARY + ListDef.FILTER),
        ("value", "Value", ListDef.SUMMARY + ListDef.FILTER),
    ], row_index='name', title="Settings", data_set="settings")

    data_pivot_map = {
        "settings": (
            ("Primary EMail", "email"),
            ("Secondary EMail", "email_secondary"),

            ("Billing City", "billing[city]"),
            ("Billing First Name", "billing[first_name]"),
            ("Billing Last Name", "billing[last_name]"),
            ("Billing Address1", "billing[address1]"),
            ("Billing Address2", "billing[address2]"),
            ("Billing Pay Mode", "billing[pay_mode]"),
            ("Billing Phone", "billing[phone]"),
            ("Billing State", "billing[state]"),
            ("Billing Card Expires", "billing[card_expires]"),
            ("Billing Postal Code", "billing[postal_code]"),
            ("Billing Country", "billing[country]"),
            ("Billing Card Number", "billing[card_number]"),

            ("Owner Org Name", "contacts[owner][org_name]"),
            ("Owner City", "contacts[owner][city]"),
            ("Owner First Name", "contacts[owner][first_name]"),
            ("Owner Last Name", "contacts[owner][last_name]"),
            ("Owner Zip", "contacts[owner][zip]"),
            ("Owner Address1", "contacts[owner][address1]"),
            ("Owner Address2", "contacts[owner][address2]"),
            ("Owner Phone", "contacts[owner][phone]"),
            ("Owner State", "contacts[owner][state]"),
            ("Owner Country", "contacts[owner][country]"),
            ("Owner Email", "contacts[owner][email]"),

            ("Admin Org Name", "contacts[admin][org_name]"),
            ("Admin City", "contacts[admin][city]"),
            ("Admin First Name", "contacts[admin][first_name]"),
            ("Admin Last Name", "contacts[admin][last_name]"),
            ("Admin Zip", "contacts[admin][zip]"),
            ("Admin Address1", "contacts[admin][address1]"),
            ("Admin Address2", "contacts[admin][address2]"),
            ("Admin Phone", "contacts[admin][phone]"),
            ("Admin State", "contacts[admin][state]"),
            ("Admin Country", "contacts[admin][country]"),
            ("Admin Email", "contacts[admin][email]"),
        )
    }

    lists = {
        "domains": domain_list_def,
        "dns": dns_list_def,
        "backup": dns_backup_list_def,
        "settings": settings_list_def
    }
    default_list = "domains"

    ipv4_re = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_re = re.compile(r'^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$')
    fqdn_re = re.compile(r'^([_a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    fqdn_add_re = re.compile(r'^(\*\.)?([_a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    num_and_fqdn_re = re.compile(r'^\d+\s+([_a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    three_num_and_fqdn_re = re.compile(r'^\d+\s+\d+\s+\d+\s+([_a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$')
    not_empty_re = re.compile(r'\S')

    dns_record_validation = {
        "A": (ipv4_re, "A record values must be a valid ip v4 address like 123.2.3.234"),
        "AAAA": (ipv4_re, "AAAA record values must be a valid ip v6 address like 2001:db8:a0b:12f0::1"),
        "TXT": (not_empty_re, "TXT record requires a non-empty value"),
        "CNAME": (fqdn_re, "CNAME record values must be a fully qualified domain name like example.com or mail.example.com"),
        "MX": (num_and_fqdn_re, "MX record values must be a number and domain name separated by white space like \"5 ALT1.ASPMX.L.GOOGLE.COM\""),
        "SRV": (three_num_and_fqdn_re, "SRV record values must be three numbers and a domain name separated by white space like \"10 60 5060 bigbox.example.com\""),
    }

    def __init__(self):
        self._api = None
        self._args = {}
        self._cache = None
        self._list = None
        self.formatter = string.Formatter()
        self.storage_path = None
        self.return_output = False

    def _cache_path(self):
        if self.storage_path is None:
            return os.path.join(os.path.expanduser("~"), ".hover-data")
        else:
            return os.path.join(os.path.realpath(self.storage_path), "hover-data")

    def read_cache(self):
        self._cache = {}
        if not self._args.no_disk_cache and os.path.exists(self._cache_path()):
            with open(self._cache_path(), 'r') as f:
                try:
                    self._cache = json.load(f)
                except ValueError:
                    return False

    def _update_cache(self, cache_entry, key, data, ts, processor=None):
        if not data:
            return False
        self._cache[cache_entry] = data[key] if processor is None else processor(data)[key]
        self._cache[cache_entry + '_ts'] = ts
        if not self._args.no_disk_cache:
            with open(self._cache_path(), 'w') as f:
                json.dump(self._cache, f)
        return True

    def purge_cache(self):
        self._cache = {}
        cache_path = self._cache_path()
        if os.path.exists(cache_path):
            os.remove(cache_path)

    def cache_data(self, root, read_if_missing=None, max_age_min=120):
        if self._cache is None:
            self.read_cache()
        api = self._api
        min_since_epoch = time.time() / 60 - max_age_min
        if root not in self._cache or self._cache[root + '_ts'] < min_since_epoch:
            api_map = {
                "domains": (api.apis['all_domains'], None),
                "dns": (api.apis['all_dns_records'], Hover.flatten_dns),
                "settings": (api.apis['all_settings'], None),
            }
            response = None
            try:
                try:
                    response = api.call(api.methods['read'], api_map[root][0], raise_on_error=True)
                except HoverException as err2:
                    if err2.error_code == "login":
                        userid = os.getenv('HOVER_USERNAME', None)
                        if userid is not None and os.getenv('HOVER_PASSWORD', None) is not None:
                            login_succeeded = api.login(os.getenv('HOVER_USERNAME', None), os.getenv('HOVER_PASSWORD', None))
                        else:
                            defualt_userid = userid
                            userid = prompt_for_input('Hover userid: ' if userid is None else 'Hover userid [{}]: '.format(userid)).strip()
                            if userid == "" and defualt_userid is not None:
                                userid = defualt_userid
                            password = prompt_for_input('Hover password: ')
                            login_succeeded = api.login(userid, password)
                        if login_succeeded:
                            response = api.call(api.methods['read'], api_map[root][0], raise_on_error=True)
                        else:
                            self.fatal_error("Unable to authenticate on hover.com as '{userid}'".format(userid=userid))
                    else:
                        raise err2
            except HoverException as err1:
                self.fatal_error("Hover api request failed due to '{}'".format("unknown server error" if err1.error is None else err1.error))

            success = self._update_cache(root, root, response, min_since_epoch, processor=api_map[root][1])

            if not success:
                return None

        return self._cache[root]

    @staticmethod
    def is_console():
        return sys.stdout.isatty()

    @staticmethod
    def get_console_size():
        import os
        env = os.environ

        def ioctl_gwinsz(gcs_fd):
            try:
                import fcntl, termios, struct, os
                gcs_cr = struct.unpack('hh', fcntl.ioctl(gcs_fd, termios.TIOCGWINSZ, '1234'))
            except:
                return
            return gcs_cr

        cr = ioctl_gwinsz(0) or ioctl_gwinsz(1) or ioctl_gwinsz(2)
        if not cr:
            try:
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_gwinsz(fd)
                os.close(fd)
            except:
                pass
        if not cr:
            cr = (os.environ.get('LINES', 25), env.get('COLUMNS', 80))

        return int(cr[1]), int(cr[0])

    @staticmethod
    def flatten_dns(data):
        flat = []
        for domain in data['domains']:
            for dns in domain['entries']:
                record = {}
                record.update(dns)
                record.update({
                    "domain_name": domain["domain_name"],
                    "domain_id": domain["id"],
                    "fqdn": domain["domain_name"] if dns["name"] == "@" else ("%s.%s" % (dns["name"], domain["domain_name"]))
                })
                flat.append(record)
        return {
            "dns": flat,
            "succeeded": data["succeeded"]
        }

    def pivot(self, data, pivots):
        records = []
        for row_num, pivot in enumerate(pivots):
            try:
                records.append({
                    "row_num": row_num,
                    "name": pivot[0],
                    "value": self.formatter.get_field(pivot[1], [], data)[0]})
            except AttributeError as e2:
                self.logger.error(repr(pivot), e2)
        return records

    def data_list(self, list_def, list_options):
        if 'sort_key' in list_options and list_options['sort_key'] is not None:
            sort_key = list_options['sort_key']
        elif list_def.data_set == 'domains':
            sort_key = lambda x: x["domain_name"]
        elif list_def.data_set == 'dns':
            sort_key = lambda x: (x["domain_name"], x["name"])
        elif list_def.data_set == 'settings':
            sort_key = None
        else:
            sort_key = None

        self.cache_data(list_def.data_set)
        if list_def.data_set in self.data_pivot_map:
            data = self.pivot(self._cache[list_def.data_set], self.data_pivot_map[list_def.data_set])
        else:
            data = self._cache[list_def.data_set]

        self._list = ListBuilder(list_def, **list_options)
        for row in data if sort_key is None else sorted(data, key=sort_key):
            self._list.add_dict(row)
        self._list.generate()

    def fatal_error(self, msg):
        if self._args.format == 'json':
            json.dump({"error": True, "reason": msg}, self._args.out, indent=2)
        if not self.return_output:
            sys.stderr.write("ERROR: " + msg + "\n")
        raise HoverError(msg)

    def resolve_fqdn(self, fqdn):

        fqdn_splitter_re = re.compile(r'^(?:(.*)[.])?((?:[a-z0-9]+(?:-[a-z0-9]+)*)[.][a-z]{2,})$')
        match = fqdn_splitter_re.match(fqdn)
        if match is None:
            self.fatal_error("Unable to split domain for add operation: '{}'".format(add_domain))
        add_subdomain = match.group(1)
        add_rootdomain = match.group(2)

        domains = self.cache_data('domains')
        if domains is None:
            self.fatal_error("Unable to retrieve nessesary domain data for account")
        root_domain = next((item for item in domains if item["domain_name"] == add_rootdomain), None)
        if root_domain is None:
            self.fatal_error("Root domain of '{}' not found in account".format(add_rootdomain))
        domain_id = root_domain["id"]

        return domain_id, add_rootdomain, add_subdomain

    def main(self, args, return_output=False):

        self.return_output = return_output
        default_output = StringIO() if return_output else sys.stdout

        parser = argparse.ArgumentParser(
            description='Flexible Hover.com registrar account access. '
            'Listing and exporting of domains, dns entries and account settings. '
            'Creation, modification and deletion of dns entries.')
        parser.add_argument('domain', metavar='DOMAIN', nargs='*',
                            help='fully qualified domain name, e.g. example.com or www.example.com, '
                                 '.exmaple.com can be used to include example.com and all subdomains')
        parser.add_argument('--refresh', '-r', action='store_true',
                            help='always refresh all domain data from server, otherwise account data is cached between invokations for up to two minutes')

        parser.add_argument('--list', '-l', action='store', dest='list_name', default=self.default_list,
                            help='specify list to display, one of ' + ', '.join(Hover.lists.keys()))
        parser.add_argument('--domain-list', '-d', action='store_const', dest='list_name', const='domains',
                            help='output list of registered domains, same as --list domains')
        parser.add_argument('--dns-list', '-n', action='store_const', dest='list_name', const='dns',
                            help='output a list of dns records, same as --list dns')
        parser.add_argument('--profile-list', action='store_const', dest='list_name', const='settings',
                            help='output list of account settings, same as --list settings')
        parser.add_argument('--backup-dns', action='store_const', dest='list_name', const='backup',
                            help='create restore script for dns records of all or specified domains')

        parser.add_argument('--add-dns', '-a', action='append', nargs=3, metavar=('DOMAIN', 'TYPE', 'VALUE'),
                            help='add a dns record for the specified domain (fqdn) followed by DNS record type and value')
        parser.add_argument('--update-dns', '-u', action='append', nargs=2, metavar=('DNS_ID', 'VALUE'),
                            help='update the value of a DNS record')
        parser.add_argument('--remove-dns', '--delete', action='append', nargs='+', metavar='DNS_ID',
                            help='delete a dns record with the specified name (fqdn)')
        parser.add_argument('--set-dns', action='append', nargs=3, metavar=('DOMAIN', 'TYPE', 'VALUE'),
                            help='set the existing dns record of the matching fqdn & type or create a new record with the specified domain (fqdn) set to the specified value,'
                                 ' an error will be caused (no work done) if more than one record exists for the fqdn of the given type')

        parser.add_argument('--detail', '-t', action='store_true',
                            help='expand number of fields shown or exported')

        parser.add_argument('--logout', action='store_true',
                            help='after any other operation, deauthorize the hover.com session')

        parser.add_argument('--output-format', '-O', action='store', dest='format', default='text',
                            help='Choices are: text (human readable) json-flat (list of record arrays) or json-mapped (dict of records)')

        parser.add_argument('--out', '-o', type=argparse.FileType('w'), default=default_output,
                            help='output file, defaults to stdout')

        parser.add_argument('--no-disk-cache', action='store_true',
                            help='do not cache data to disk or use existing cached data')

        parser.add_argument('--filter', '-f', action='store',
                            help='filter names that include the specified string')

        parser.add_argument('--ignore-console-width', action='store_true',
                            help='don\'t limit output to console width')

        parser.add_argument('--dbg-dump-list-defs', action='store_true',
                            help='dump list def info')

        parser.add_argument('--storage-path', '-s', default=None, action='store',
                            help='path where persistant data & temp data files can be stored by the tool')

        parser.add_argument('--trace', action='store_true',
                            help='Enable trace output, REST api logging')
        parser.add_argument('--debug', action='store_true',
                            help='Enable debug output, program execution detail')
        parser.add_argument('--verbose', action='store_true',
                            help='Enable info output, informational detail')

        if Hover.logger.isEnabledFor(logging.INFO):
            if sys.version_info < (3, 3):
                from pipes import quote as shell_quote
            else:
                from shlex import quote as shell_quote
            Hover.logger.info("Parameters: %s" % " ".join([shell_quote(s) for s in args[1:]]))

        self._args = parser.parse_args(args[1:])

        if self._args.storage_path is not None:
            self.storage_path = os.path.realpath(self._args.storage_path)
            if not os.access(self.storage_path, os.W_OK):
                self.fatal_error("storage path '{}' must be writable".format(self._args.storage_path))

            Hover.logger.debug("storage path: %s" % self.storage_path)

        self._api = HoverAPI(storage_path=self.storage_path)

        if self._args.dbg_dump_list_defs:
            print("\ndomain_list_def", file=self.out)
            hover.domain_list_def.dump()
            print("\ndns_list_def", file=self.out)
            hover.dns_list_def.dump()
            print("\nsettings_list_def", file=self.out)
            hover.settings_list_def.dump()
            return (0, '') if return_output else 0

        if self._args.refresh:
            self.purge_cache()

        list_options = {
            "detail": self._args.detail,
            "out": self._args.out,
            "fmt": self._args.format,
            "filter": self._args.filter,
            "for_domains": self._args.domain,
            "max_line_len": self.get_console_size()[0] if self._args.format == 'text' and self.is_console() else None
        }

        if self._args.set_dns is not None and len(self._args.set_dns) > 0:

            dns_records = self.cache_data('dns')
            multiple_matches = False

            for args in self._args.set_dns:
                match = None
                set_fqdn = args[0].strip().lower()
                set_type = args[1].strip().upper()
                set_value = args[2].strip()

                for dns_rec in dns_records:
                    if dns_rec['fqdn'] == set_fqdn and dns_rec['type'] == set_type:
                        if match is not None:
                            if match is not True:
                                multiple_matches = True
                                self.error("Existing record: {id} {fqdn} {type} {content}".format(**match))
                                match = True
                            self.error("Existing record: {id} {fqdn} {type} {content}".format(**dns_rec))
                        else:
                            match = dns_rec

                if match is not None:
                    if match is not True:
                        update_rec = [match['id'], set_value]
                        if self._args.update_dns is None:
                            self._args.update_dns = update_rec
                        else:
                            self._args.update_dns.append(update_rec)
                        self.trace("Set for {0} {1} {2} generated update-dns operation for {3}".format(*(args + [match['id']])))
                else:
                    if self._args.add_dns is None:
                        self._args.add_dns = [args]
                    else:
                        self._args.add_dns.append(args)
                    self.trace("Set for {0} {1} {2} generated add-dns operation".format(*args))

            if multiple_matches:
                self.fatal_error("set-dns operation with multiple existing dns record matches")

        if self._args.add_dns is not None and len(self._args.add_dns) > 0:

            errors = 0
            add_domain_list = []
            for args in self._args.add_dns:
                if len(args) != 3:
                    self.fatal_error("adding dns entry requires three parameters, a domain name, a record type and a record value")

                add_domain = args[0].strip().lower()
                add_domain_list.append(add_domain)
                add_type = args[1].strip().upper()
                add_value = args[2].strip().strip()
                if self.fqdn_re.match(add_domain) is None:
                    self.fatal_error("first parameter for adding a DNS entry should be a fully qualified domain name")
                elif add_type not in self.dns_record_validation:
                    self.fatal_error("second parameter for adding a DNS entry should be one of " + ", ".join(HoverAPI.dns_types))
                add_re, add_re_error = self.dns_record_validation[add_type]
                if add_re.match(add_value) is None:
                    self.fatal_error(add_re_error.format(value=add_value))

                domain_id, add_rootdomain, add_subdomain = self.resolve_fqdn(add_domain)

                dns_record = {"name": add_subdomain, "type": add_type, "content": add_value}
                method = HoverAPI.methods['create']
                path = HoverAPI.apis['dns_records_by_domain'].format(domain=domain_id)
                self.trace("Request: %s %s" % (method, path))
                self.trace("Request Data: %r" % repr(dns_record))
                response = self._api.call(method, path, dns_record)

                if response is None:
                    errors += 1

                if self.logger.isEnabledFor(logging.TRACE):
                    message = "DNS record for {1} with type {2} and value {3}: {0}"
                    self.trace(message.format("ERROR" if response is None else "SUCCESS", *args))

            if errors > 0:
                self.logger.log(logging.ERROR, "There were {count} errors processing dns additions", count=errors)
            self.verbose("DNS records created: {count}".format(count=len(self._args.add_dns)-errors))
            list_options["for_domains"] = add_domain_list
            list_options["filter"] = None
            self.purge_cache()
            self.data_list(self.lists["dns"], list_options)

        if self._args.remove_dns is not None:

            dns_records = self.cache_data('dns')

            list_options["filter"] = None
            list_options["for_domains"] = None

            delete_list = ListBuilder(self.dns_list_def, **list_options)

            for dns_id in itertools.chain.from_iterable(self._args.remove_dns):
                dns_record = next((item for item in dns_records if item["id"] == dns_id), None)
                if dns_record is None:
                    self.fatal_error("dns id '{}' not found".format(dns_id))

                response = self._api.call(HoverAPI.methods["delete"], self._api.apis["dns_record"].format(dns_id=dns_id))

                delete_list.add_dict(dns_record)
                self.debug("Delete id='{}' response='{}'".format(dns_id, response))

            if list_options["fmt"] == 'text':
                print("DNS Records Deleted", file=list_options["out"])
            delete_list.generate()

            self.purge_cache()

        if self._args.update_dns is not None:
            errors = 0
            add_domain_list = []
            for args in self._args.update_dns:
                dns_id = str(args[0]).strip()
                update_value = str(args[1]).strip()
                self.debug("Update: id='{}' - value='{}'".format(dns_id, update_value))

                dns_record = {"content": update_value}
                method = HoverAPI.methods["update"]
                path = self._api.apis["dns_record"].format(dns_id=dns_id)
                response = self._api.call(method, path, dns_record)

                if response is None:
                    errors += 1

                if self.logger.isEnabledFor(logging.TRACE):
                    result = "ERROR" if response is None else "SUCCESS"
                    message = "DNS record update for {} with value {}: {}"
                    self.trace(message.format(dns_id, update_value, result))

            self.purge_cache()
            dns_ids_updated = [args[0] for args in self._args.update_dns]
            list_options['filter'] = lambda row: row['id'] in dns_ids_updated
            self.data_list(self.lists["dns"], list_options)

        if (self._args.add_dns is None and
                self._args.set_dns is None and
                self._args.remove_dns is None and
                self._args.update_dns is None):

            list_name = self._args.list_name
            if list_name in self.lists:
                self.data_list(self.lists[list_name], list_options)
            else:
                self.fatal_error("Unknown list '{0}'".format(list_name))

        if self._args.logout:
            self._api.logout()
            self.purge_cache()

        return (0, default_output.getvalue()) if return_output else 0

    def error(self, *args, **kwargs):
        self.logger.log(logging.ERROR, *args, **kwargs)

    def verbose(self, *args, **kwargs):
        self.logger.log(logging.INFO, *args, **kwargs)

    def debug(self, *args, **kwargs):
        self.logger.log(logging.DEBUG, *args, **kwargs)

    def trace(self, *args, **kwargs):
        self.logger.log(logging.TRACE, *args, **kwargs)


if __name__ == "__main__":

    if os.path.exists(sys.argv[0] + ".log_conf.json"):
        import logging.config
        import json

        with open(sys.argv[0] + ".log_conf.json") as config:
            logging.config.dictConfig(json.load(config))
    if not hasattr(logging, 'TRACE'):
        logging.TRACE = 5
        logging.addLevelName(logging.TRACE, "TRACE")
    if "--trace" in sys.argv:
        logging.basicConfig(level=logging.TRACE)
    elif "--debug" in sys.argv:
        logging.basicConfig(level=logging.DEBUG)
    elif "--verbose" in sys.argv:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig()

    hover = Hover()
    try:
        rc = hover.main(sys.argv)
        if rc != 0:
            sys.exit(rc)
    except HoverError as e:
        pass
