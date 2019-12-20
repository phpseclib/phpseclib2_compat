<?php
namespace phpseclib\Net;

use phpseclib3\Net\SSH2 as SSH;
use phpseclib\Crypt\RSA;

class SSH2 extends SSH
{
    /**
     * Login
     *
     * The $password parameter can be a plaintext password, a \phpseclib3\Crypt\RSA object or an array
     *
     * @param string $username
     * @param $args[] param mixed $password
     * @return bool
     * @see self::_login()
     * @access public
     */
    public function login($username, ...$args)
    {
        foreach ($args as &$arg) {
            if ($arg instanceof RSA) {
                $arg = $arg->getPrivateKeyObject();
                if (!$arg) {
                    return false;
                }
            }
        }

        return parent::login($username, ...$args);
    }
}