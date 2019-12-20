# phpseclib2_compat

[![Build Status](https://travis-ci.org/phpseclib/phpseclib2_compat.svg?branch=master)](https://travis-ci.org/phpseclib/mcrypt_compat)

phpseclib 2.0 polyfill built with phpseclib 3.0

## Installation

With [Composer](https://getcomposer.org/), you'll first need to add `minimum-stability` to your composer.json, thusly:

```
{
    "minimum-stability": "dev"
}
```

After that doing the following via the CLI will be sufficient:

```
composer require phpseclib/phpseclib2_compat:dev-master
```

Once 3.0.0 is officially released the `minimum-stability` requirement will go away.