<?php

/**
 * Pure-PHP implementation of SFTP.
 *
 * PHP version 5
 *
 * Currently only supports SFTPv2 and v3, which, according to wikipedia.org, "is the most widely used version,
 * implemented by the popular OpenSSH SFTP server".  If you want SFTPv4/5/6 support, provide me with access
 * to an SFTPv4/5/6 server.
 *
 * The API for this library is modeled after the API from PHP's {@link http://php.net/book.ftp FTP extension}.
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $sftp = new \phpseclib\Net\SFTP('www.domain.tld');
 *    if (!$sftp->login('username', 'password')) {
 *        exit('Login Failed');
 *    }
 *
 *    echo $sftp->pwd() . "\r\n";
 *    $sftp->put('filename.ext', 'hello, world!');
 *    print_r($sftp->nlist());
 * ?>
 * </code>
 *
 * @category  Net
 * @package   SFTP
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2009 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Net;

use phpseclib\Crypt\RSA;

class SFTP extends \phpseclib3\Net\SFTP
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
                if (!$arg instanceof \phpseclib3\Crypt\Common\PrivateKey) {
                    return false;
                }
            }
        }

        return parent::login($username, ...$args);
    }

    /**
     * Parse Attributes
     *
     * See '7.  File Attributes' of draft-ietf-secsh-filexfer-13 for more info.
     *
     * @param string $response
     * @return array
     * @access private
     */
    protected function parseAttributes(&$response)
    {
        $r = parent::parseAttributes($response);
        if (isset($r['mode'])) {
            $r['permissions'] = $r['mode'];
        }
        return $r;
    }

    /**
     * Defines how nlist() and rawlist() will be sorted - if at all.
     *
     * If sorting is enabled directories and files will be sorted independently with
     * directories appearing before files in the resultant array that is returned.
     *
     * Any parameter returned by stat is a valid sort parameter for this function.
     * Filename comparisons are case insensitive.
     *
     * Examples:
     *
     * $sftp->setListOrder('filename', SORT_ASC);
     * $sftp->setListOrder('size', SORT_DESC, 'filename', SORT_ASC);
     * $sftp->setListOrder(true);
     *    Separates directories from files but doesn't do any sorting beyond that
     * $sftp->setListOrder();
     *    Don't do any sort of sorting
     *
     * @param $args[]
     * @access public
     */
    public function setListOrder(...$args)
    {
        $this->sortOptions = [];
        if (empty($args)) {
            return;
        }
        $len = count($args) & 0x7FFFFFFE;
        for ($i = 0; $i < $len; $i+=2) {
            if ($args[$i] == 'permissions') {
                $args[$i] = 'mode';
            }
            $this->sortOptions[$args[$i]] = $args[$i + 1];
        }
        if (!count($this->sortOptions)) {
            $this->sortOptions = ['bogus' => true];
        }
    }

    /**
     * Returns the file size, in bytes, or false, on failure
     *
     * Files larger than 4GB will show up as being exactly 4GB.
     *
     * @param string $filename
     * @return mixed
     * @access public
     */
    public function size($filename)
    {
        return $this->filesize($filename);
    }
}