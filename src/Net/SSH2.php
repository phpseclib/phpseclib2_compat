<?php

/**
 * Pure-PHP implementation of SSHv2.
 *
 * PHP version 5
 *
 * Here are some examples of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $ssh = new \phpseclib\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->exec('pwd');
 *    echo $ssh->exec('ls -la');
 * ?>
 * </code>
 *
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $key = new \phpseclib\Crypt\RSA();
 *    //$key->setPassword('whatever');
 *    $key->loadKey(file_get_contents('privatekey'));
 *
 *    $ssh = new \phpseclib\Net\SSH2('www.domain.tld');
 *    if (!$ssh->login('username', $key)) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $ssh->read('username@username:~$');
 *    $ssh->write("ls -la\n");
 *    echo $ssh->read('username@username:~$');
 * ?>
 * </code>
 *
 * @category  Net
 * @package   SSH2
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */


namespace phpseclib\Net;

use phpseclib\Crypt\RSA;

class SSH2 extends \phpseclib3\Net\SSH2
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
                $arg = $arg->getKeyObject();
                if (!$arg) {
                    return false;
                }
            }
        }

        return parent::login($username, ...$args);
    }
}