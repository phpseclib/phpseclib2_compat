<?php

/**
 * Pure-PHP X.509 Parser
 *
 * PHP version 5
 *
 * Encode and decode X.509 certificates.
 *
 * The extensions are from {@link http://tools.ietf.org/html/rfc5280 RFC5280} and
 * {@link http://web.archive.org/web/19961027104704/http://www3.netscape.com/eng/security/cert-exts.html Netscape Certificate Extensions}.
 *
 * Note that loading an X.509 certificate and resaving it may invalidate the signature.  The reason being that the signature is based on a
 * portion of the certificate that contains optional parameters with default values.  ie. if the parameter isn't there the default value is
 * used.  Problem is, if the parameter is there and it just so happens to have the default value there are two ways that that parameter can
 * be encoded.  It can be encoded explicitly or left out all together.  This would effect the signature value and thus may invalidate the
 * the certificate all together unless the certificate is re-signed.
 *
 * @category  File
 * @package   X509
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2012 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      http://phpseclib.sourceforge.net
 */

namespace phpseclib\File;

use phpseclib\Crypt\RSA;

/**
 * Pure-PHP X.509 Parser
 *
 * @package X509
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class X509
{
    /**
     * The X509 object
     *
     * @var \phpseclib3\File\X509
     * @access private
     */
    private $x509;

    /**
     * Default Constructor.
     *
     * @return \phpseclib\File\X509
     * @access public
     */
    public function __construct()
    {
        // we don't extend phpseclib3\File\X509 because the setPublicKey() and setPrivateKey() methods
        // have different method signatures
        $this->x509 = new \phpseclib3\File\X509();
    }

    /**
     *  __call() magic method
     *
     * @access public
     */
    public function __call($name, $args)
    {
        foreach ($args as &$arg) {
            if ($arg instanceof \phpseclib3\File\X509) {
                $arg = $arg->x509;
            }
        }
        $result = $this->x509->$name(...$args);
        if ($result instanceof \phpseclib3\File\X509) {
            $temp = new static;
            $temp->x509 = $result;
            return $temp;
        }
        return $result;
    }

    /**
     * Set public key
     *
     * Key needs to be a \phpseclib\Crypt\RSA object
     *
     * @param object $key
     * @access public
     * @return bool
     */
    public function setPublicKey($key)
    {
        if (!$key instanceof RSA) {
            return;
        }
        $key = $key->getKeyObject();
        if ($key instanceof \phpseclib3\Crypt\Common\PublicKey) {
            $this->x509->setPublicKey($key);
        }
    }

    /**
     * Set private key
     *
     * Key needs to be a \phpseclib\Crypt\RSA object
     *
     * @param object $key
     * @access public
     */
    public function setPrivateKey($key)
    {
        if (!$key instanceof RSA) {
            return;
        }
        $key = $key->getKeyObject();
        if ($key instanceof \phpseclib3\Crypt\Common\PrivateKey) {
            $this->x509->setPrivateKey($key);
        }
    }
}