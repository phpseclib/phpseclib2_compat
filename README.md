# phpseclib2_compat

[![Build Status](https://travis-ci.com/phpseclib/phpseclib2_compat.svg?branch=1.0)](https://travis-ci.com/phpseclib/phpseclib2_compat)

phpseclib 2.0 polyfill built with phpseclib 3.0

## Overview

phpseclib 3.0 breaks backwards compatability with phpseclib 2.0. Most notably, public keys work completely differently. So let's say you wanted to use phpseclib 3.0 whilst some of your other dependencies still use phpseclib 2.0. What would you do in that instance?

That's where phpseclib2_compat comes into play. Require phpseclib/phpseclib:~3.0 and phpseclib/phpseclib2_compat:~1.0 and you're dependencies will magically start using phpseclib 3.0 even if they don't know it.

Using phpseclib2_compat will actually bring a few enhancements to your dependencies. For example, while phpseclib 2.0 only supports RSA keys phpseclib2_compat sports support for ECDSA / DSA / Ed25519 / Ed449 keys.

Consider this code sample:

```php
use phpseclib\Crypt\RSA;

$rsa = new RSA;
$rsa->loadKey('ecdsa private key');

$ssh = new SSH2('website.com');
$ssh->login('username', $rsa);
```
That'll work with phpseclib2_compat, even with an ECDSA private key, whereas in phpseclib 2.0 it would not work.

SSH1 and SCP are not supported but those were likely never frequently used anyway.

## Installation

With [Composer](https://getcomposer.org/):

```
composer require phpseclib/phpseclib2_compat:~1.0
```