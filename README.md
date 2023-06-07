# Apache2 Module implementing Two-Factor-Authentication using TOTP codes

Implementation follows the [Google Authenticator open source standard](https://github.com/google/google-authenticator).

## Features

1. Authentication using TOTP codes and scratch codes
2. Invalidate codes and scratch codes after use
3. Rate limit login attemps
4. Authentication using session tokens using [mod_seesion_cookie](https://github.com/apache/httpd/blob/trunk/modules/session/mod_session_cookie.c)
5. Per user configuration in Google Authenticator file format

## Build

### Debian Linux and its derivative distributions

1. Install build dependencies:

```
apt-get install apache2-dev
```

2. Checkout the repository and enter its root directory:

```
git clone https://github.com/breezerider/totp-authenticator-apache-module.git
cd totp-authenticator-apache-module
```

3. Build using [`make`](https://www.gnu.org/software/make/) to build the package:

```
make
make install
```

4. Extend you existing site configuration with setting for basic or digest authetication:

```
<VirtualHost ...>

<Directory "/path/to/protected/content/">
...
# TOTP authentication using basic authentication
AuthType Basic
AuthName "My Test" 
AuthBasicProvider "totp"

# TOTP authenticator settings
Require valid-user 
TOTPAuthTokenDir "/path/to/google_autheticator" # must readable to user running Apache service
TOTPAuthStateDir "/path/to/state" # must readable and writable to user running Apache service
TOTPAuthExpires 360 # optional, default 3600

</Directory>

</VirtualHost>
```

5. Enable the `authn_totp`:

```
a2enmod authn_totp
```

6. Check configuration:

```
apachectl configtest
```

7. If everything checks out, then restart the Apache service:

```
apachectl restart
```

## Troubleshooting

Obviously, check your Apache log file. One very important thing is to make sure you have proper time synchronization. Use of a service such as NTP is highly recommended. Using a larger window of concurrently valid codes can help compensate for slop in time sync.


## License

The ASF licenses this software to You under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
