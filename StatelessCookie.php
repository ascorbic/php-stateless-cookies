<?php
require_once 'PasswordHash.php';

/**
 * Implements a stateless session cookie and user account mechanism.
 * 
 * This is based on the scheme described by Steven J. Murdoch in "Hardened Stateless Session Cookies", which is
 * a hardened version of the protocol described by Wu et al. and Liu et al. as used by Wordpress.
 * See http://www.cl.cam.ac.uk/~sjm217/papers/protocols08cookies.pdf
 * 
 * Copyright (c) 2011 Matt Kane (http://ascorbic.github.com/)
 * Licensed under the MIT license.
 *
 */

class StatelessCookie {
    protected $secret;
    
    function __construct($secret) {
        if(!CRYPT_BLOWFISH) {
            throw new Exception("CRYPT_BLOWFISH is required");
        }
        if(!class_exists("PasswordHash")) {
            throw new Exception("PasswordHash not found. Please include phpass library");
            
        }
        if(empty($secret)) {
            throw new Exception("Please include a server secret");
        }
        $this->secret = $secret;
    }
    
    
    /**
     * Given a password, returns a salt/hash authenticator string.
     * 
     * The password is hashed using phpass/blowfish. 
     * The salt and hash are extracted from the string, then the hash is further hashed using unsalted sha256.
     * The original salt is then prepended to this, along with the string '$X$' to make it clear this isn't
     * a normal phpass hash. Perhaps there's a better way of doing this?
     *
     * @param string $password 
     * @return string $hash
     */
    function hashPassword($password) {
        $hasher = new PasswordHash(8, FALSE);
        $hash = $hasher->HashPassword($password);
        if(strlen($hash) != 60) {
            throw new Exception("Error creating hash");
        }
        $salt =  substr($hash, 0, 29);
        $c = substr($hash, 29);
        $authenticator = hash('sha256', $c);
        return '$X$' . $salt . $authenticator;
    }
    
    /**
     * Verifies a password against the stored hash.
     *
     * If correct, the authenticator string is returned, which can be used to build a cookie.
     * @param string $password 
     * @param string $hash 
     * @return mixed
     */
    
    function login($password, $hash) {   
        if(substr($hash, 0, 3) != '$X$') {
            return false;
        }
        $salt = substr($hash, 3, 29);
        $auth = substr($hash, 32);
    
        $check = crypt($password, $salt);
        $s2 = substr($check, 0, 29);
        $c = substr($check, 29);    
    
        if($s2 != $salt) {
            return false;   
        }
    
        $hashhash = hash('sha256', $c);
    
        if($hashhash != $auth) {
            return false;
        }
        return $c;
    }

    /**
     * Generates a hardened cookie string with digest.
     *
     * @param int $expires Expiry time (seconds since epoch)
     * @param string $data e.g. username
     * @param string $auth Authenticator string, returned by login()
     * @return string Cookie string. n.b. this isn't a full set-cookie string
     */
    function buildCookie($expires, $data, $auth) {        
        if(!$expires) {
            throw new Exception("Invalid expiry time");
        }
        $cookie = sprintf("exp=%s&data=%s&auth=%s", urlencode($expires), urlencode($data), urlencode($auth));
        $mac = hash_hmac("sha256", $cookie, $this->secret);
        return $cookie . '&digest=' . urlencode($mac);
    }


    /**
     * Extracts the data (username) from the cookie string. 
     * n.b. This does not verify the cookie! This is just so you can get the user's hash from the database.
     *
     * @return string The data
     **/
    public function getCookieData($cookie) {
        parse_str($cookie, &$vars);
        return $vars['data'];
    }

    /**
     * Verifies the expiry and MAC for the cookie, and checks the auth value against the stored hash
     *
     * @param string $cookie String from the client
     * @param string $hash Stored hash for the user 
     * @return void
     */
    function checkCookie($cookie, $hash) {
        parse_str($cookie, &$vars);
        
        if(empty($vars['exp']) || $vars['exp'] < time()) {
            //Expired
            return false;
        }
        
        $str =  $this->buildCookie($vars['exp'], $vars['data'], $vars['auth']);
        if($cookie != $str) {
            return false;
        }
        if(substr($hash, 0, 3) != '$X$') {
             return false;
        }
        $auth = substr($hash, 32);
        
        $hashhash = hash('sha256', $vars['auth']);
        if($hashhash != $auth) {
            return false;
        }
        
        return $vars;
    }
}