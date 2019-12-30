<?php

/**
 * Pure-PHP implementation of Twofish.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * Useful resources are as follows:
 *
 *  - {@link http://en.wikipedia.org/wiki/Twofish Wikipedia description of Twofish}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $twofish = new \phpseclib\Crypt\Twofish();
 *
 *    $twofish->setKey('12345678901234567890123456789012');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $twofish->decrypt($twofish->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Twofish
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

/**
 * Pure-PHP implementation of Twofish.
 *
 * @package Twofish
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Twofish extends Base
{
    /**
     * Sets the key length
     *
     * Keys can be between 1 and 256 bytes long.
     *
     * @access public
     * @param int $length
     */
    public function setKeyLength($length)
    {
        switch (true) {
            case $length <= 128:
                $length = 128;
                break;
            case $length <= 192:
                $length = 192;
                break;
            default:
                $length = 256;
        }

        parent::setKeyLength($length);
    }
}