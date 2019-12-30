<?php

/**
 * Pure-PHP implementation of Blowfish.
 *
 * Uses mcrypt, if available, and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * Useful resources are as follows:
 *
 *  - {@link http://en.wikipedia.org/wiki/Blowfish_(cipher) Wikipedia description of Blowfish}
 *
 * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $blowfish = new \phpseclib\Crypt\Blowfish();
 *
 *    $blowfish->setKey('12345678901234567890123456789012');
 *
 *    $plaintext = str_repeat('a', 1024);
 *
 *    echo $blowfish->decrypt($blowfish->encrypt($plaintext));
 * ?>
 * </code>
 *
 * @category  Crypt
 * @package   Blowfish
 * @author    Jim Wigginton <terrafrost@php.net>
 * @author    Hans-Juergen Petrich <petrich@tronic-media.com>
 * @copyright 2007 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\Crypt;

/**
 * Pure-PHP implementation of Blowfish.
 *
 * @package Blowfish
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Blowfish extends Base
{
    /**
     * Sets the key length.
     *
     * Key lengths can be between 32 and 448 bits.
     *
     * @access public
     * @param int $length
     */
    public function setKeyLength($length)
    {
        if ($length < 32) {
            $length = 32;
        } elseif ($length > 448) {
            $length = 448;
        }
        parent::setKeyLength($length);
    }
}