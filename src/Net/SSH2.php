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

class SSH2
{
    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH2::getLog()
    */
    /**
     * Returns the message numbers
     */
    const LOG_SIMPLE = 1;
    /**
     * Returns the message content
     */
    const LOG_COMPLEX = 2;
    /**
     * Outputs the content real-time
     */
    const LOG_REALTIME = 3;
    /**
     * Dumps the content real-time to a file
     */
    const LOG_REALTIME_FILE = 4;
    /**
     * Make sure that the log never gets larger than this
     */
    const LOG_MAX_SIZE = 1048576; // 1024 * 1024
    /**#@-*/

    /**#@+
     * @access public
     * @see \phpseclib\Net\SSH2::read()
    */
    /**
     * Returns when a string matching $expect exactly is found
     */
    const READ_SIMPLE = 1;
    /**
     * Returns when a string matching the regular expression $expect is found
     */
    const READ_REGEX = 2;
    /**
     * Returns whenever a data packet is received.
     *
     * Some data packets may only contain a single character so it may be necessary
     * to call read() multiple times when using this option
     */
    const READ_NEXT = 3;
    /**#@-*/

    /**
     * The SSH2 object
     *
     * @var \phpseclib3\File\SSH2
     * @access private
     */
    private $ssh;

    /**
     * Default Constructor.
     *
     * $host can either be a string, representing the host, or a stream resource.
     *
     * @param mixed $host
     * @param int $port
     * @param int $timeout
     * @see self::login()
     * @return \phpseclib\Net\SSH2
     * @access public
     */
    function __construct($host, $port = 22, $timeout = 10)
    {
        $this->ssh = new \phpseclib3\Net\SSH2($host, $port, $timeout);
    }

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

        try {
            return $this->ssh->login($username, ...$args);
        } catch (\Exception $e) {
            user_error($e->getMessage());
            return false;
        }
    }

    /**
     *  __call() magic method
     *
     * @access public
     */
    public function __call($name, $args)
    {
        try {
            return $this->ssh->$name(...$args);
        } catch (\Exception $e) {
            user_error($e->getMessage());
        }
    }
}