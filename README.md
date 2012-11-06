PHP stateless cookies
============

Implements a stateless session cookie and user account mechanism.
This is based on the scheme described by Steven J. Murdoch in "Hardened Stateless Session Cookies", which is
a hardened version of the protocol described by Wu et al. and Liu et al. which are used by Wordpress.
See http://www.cl.cam.ac.uk/~sjm217/papers/protocols08cookies.pdf
 
Copyright © 2011 Matt Kane (http://ascorbic.github.com/)
Licensed under the MIT license.

Usage
=======

Pass the constructor your secret server key.

```php
    $secret = "sekrit";
    $cookies = new StatelessCookie($secret);
```

A user signs up:

```php
    $hash = $cookies->hashPassword("password123");

    //Store $hash in your user database.
```

A user logs-in. Retrieve $storedhash from your database.

```php
    $auth = $cookies->login("password123", $storedhash);
    $cookie = $cookies->buildCookie(strtotime("+1 hour"), 'admin', $auth);
    setcookie("auth", $cookie);
```

On future pageloads.

```php
    $cookie = $_COOKIE['auth'];
    $user = $cookies->getCookieData($cookie);
    // Fetch the user's stored hash from the database...
    $result = $cookies->checkCookie($cookie, $storedhash);
    
    // $result is false if the cookie is invalid, or the cookie vars as an array if it's valid.
```

Requirements
=======
* phpass: http://www.openwall.com/phpass/

* PHP with Blowfish support. This is implemented internally in 5.3. Earlier versions require system support for it.