<?php

/**
 * Pure-PHP implementation of RC2.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * Useful resources are as follows:
 *
 *  - {@link http://tools.ietf.org/html/rfc2268}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $rc2 = new \phpseclib\Crypt\RC2();
 *
 *    $rc2->setKey('abcdefgh');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $rc2->decrypt($rc2->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category Crypt
 * @package  RC2
 * @author   Patrick Monnerat <pm@datasphere.ch>
 * @license  http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link     http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

/**
 * Pure-PHP implementation of RC2.
 *
 * @package RC2
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class RC2 extends Base
{
    /**
     * Sets the key length.
     *
     * Valid key lengths are 8 to 1024.
     * Calling this function after setting the key has no effect until the next
     *  \phpseclib\Crypt\RC2::setKey() call.
     *
     * @access public
     * @param int $length in bits
     */
    public function setKeyLength($length)
    {
        if ($length < 8) {
            $length = 1;
        } elseif ($length > 1024) {
            $length = 128;
        }
        parent::setKeyLength($length);
    }
}