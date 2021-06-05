proftpd-mod_auth_web
====================

Status
------
[![GitHub Actions CI Status](https://github.com/proftpd/mod_auth_web/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/proftpd/mod_auth_web/actions/workflows/ci.yml)

`mod_auth_web` is a ProFTPD module that authenticates users against a web URL,
such as the login form for a remote web site. It is useful for
authenticating users against a service that provides web access, but no
programmatic means (such as an API) for authentication.

`mod_auth_web` is no longer actively maintained. It works with the most recent
ProFTPD release, but is not guaranteed to continue working with new ProFTPD
releases.


Installation
============

You can add `mod_auth_web` to an existing ProFTPD installation by building it
as a DSO: http://www.proftpd.org/docs/howto/DSO.html


Sample Configuration
====================

This sample configuration illustrates authentication against Yahoo!. Users
must log in via FTP as `yahoousername@yahoo.com` and will have the UID, GID,
and home directory of the user named `example`.
```
	AuthWebUserRegex @yahoo.com$
	AuthWebURL https://login.yahoo.com/config/login?
	AuthWebUsernameParamName login
	AuthWebPasswordParamName passwd
	AuthWebLocalUser example
	AuthWebLoginFailedString "Invalid ID or password."
	AuthWebRequireHeader "HTTP/1.1 302 Found"
	AuthWebRequireHeader "Location: https://login.yahoo.com/config/verify?.done=http%3a//www.yahoo.com"
```

Directives
==========

AuthWebUserRegex
----------------
* Syntax: AuthWebUserRegex _regex_
* Default: `.*`
* Context: server config, `<VirtualHost>`, `<Global>`

Configures which usernames should be processed by mod_auth_web. The
_regex_ parameter is a standard (not extended) regular expression. If
a username matches this regular expression, it will be processed; otherwise,
the login request will be ignored by mod_auth_web and other ProFTPD modules
will be allowed to process it.


AuthWebURL
----------
* Syntax: AuthWebURL _url_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures the URL to `POST` to when
authenticating users. `AuthWebURL` can be configured on a per-
`<VirtualHost>` basis, so that virtual FTP servers can use
different URLs to authenticate against different services or to pass URL
parameters identifying the `<VirtualHost>`.


AuthWebUsernameParamName
------------------------
* Syntax: AuthWebUsernameParamName _queryparam_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures the parameter name to use for the username when
submitting `POST` requests to `AuthWebURL`.

See also: `AuthWebPasswordParamName`


AuthWebPasswordParamName
------------------------
* Syntax: AuthWebPasswordParamName _path_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures the parameter name to use for the password when
submitting `POST` requests to `AuthWebURL`.

See also: `AuthWebUsernameParamName`


AuthWebLocalUser
----------------
* Syntax: AuthWebLocalUser _username_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures the local username to use for all users
authenticated by mod_auth_web. All users must have certain
information, such as user ID (UID), group ID, and home directory, in order
to log in. Since web-based authentication provides no way to retrieve this
information, users authenticated by mod_auth_web are given the
user information for _username_. The username will remain the same as
the user entered it when logging in, but all other account information (UID,
GID, home directory, etc.) will be based on this local user. 


AuthWebLoginFailedString
------------------------
* Syntax: AuthWebLoginFailedString _string_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures a string that the remote web server sends to
indicate authentication failure. If the remote web server's response body
contains _string_, authentication will be rejected. Only one
`AuthWebLoginFailedString` may be configured.

See also: `AuthWebRequireHeader`


AuthWebRequireHeader
--------------------
* Syntax: AuthWebRequireHeader _header_
* Default: None
* Context: server config, `<VirtualHost>`, `<Global>`

This directive configures a HTTP header that must be present for
authentication to succeed. Multiple `AuthWebRequireHeader`
directives may be used, and all configured headers must be present in the
web server's response for authentication to succeed.

See also: `AuthWebLoginFailedString`


History
=======

* v1.1.2 (26 Apr 2014)
 * Emit a useful error message on curl failure.
 * Use proftpd's regex type and supporting functions.

* v1.1.1 (17 Mar 2011)
 * Sync with ProFTPD pr_regexp_alloc() API change after Bug #3609
   (will likely be in ProFTPD 1.3.4 release candidates and later).

* v1.1 (9 June 2007)
 * URL-encode usernames and passwords when submitting them to the remote
   web server, removing the character restrictions previously in place.

* v1.0 (17 Feb 2007)
 * Initial release.
