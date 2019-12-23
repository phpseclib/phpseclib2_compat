<?php

/**
 * Pure-PHP arbitrary precision integer arithmetic library.
 *
 * Supports base-2, base-10, base-16, and base-256 numbers.  Uses the GMP or BCMath extensions, if available,
 * and an internal implementation, otherwise.
 *
 * PHP version 5
 *
 * {@internal (all DocBlock comments regarding implementation - such as the one that follows - refer to the
 * {@link self::MODE_INTERNAL self::MODE_INTERNAL} mode)
 *
 * BigInteger uses base-2**26 to perform operations such as multiplication and division and
 * base-2**52 (ie. two base 2**26 digits) to perform addition and subtraction.  Because the largest possible
 * value when multiplying two base-2**26 numbers together is a base-2**52 number, double precision floating
 * point numbers - numbers that should be supported on most hardware and whose significand is 53 bits - are
 * used.  As a consequence, bitwise operators such as >> and << cannot be used, nor can the modulo operator %,
 * which only supports integers.  Although this fact will slow this library down, the fact that such a high
 * base is being used should more than compensate.
 *
 * Numbers are stored in {@link http://en.wikipedia.org/wiki/Endianness little endian} format.  ie.
 * (new \phpseclib\Math\BigInteger(pow(2, 26)))->value = array(0, 1)
 *
 * Useful resources are as follows:
 *
 *  - {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf Handbook of Applied Cryptography (HAC)}
 *  - {@link http://math.libtomcrypt.com/files/tommath.pdf Multi-Precision Math (MPM)}
 *  - Java's BigInteger classes.  See /j2se/src/share/classes/java/math in jdk-1_5_0-src-jrl.zip
 *
 * Here's an example of how to use this library:
 * <code>
 * <?php
 *    $a = new \phpseclib\Math\BigInteger(2);
 *    $b = new \phpseclib\Math\BigInteger(3);
 *
 *    $c = $a->add($b);
 *
 *    echo $c->toString(); // outputs 5
 * ?>
 * </code>
 *
 * @category  Math
 * @package   BigInteger
 * @author    Jim Wigginton <terrafrost@php.net>
 * @copyright 2006 Jim Wigginton
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 */

namespace phpseclib\Math;

use phpseclib3\Math\BigInteger as BigInteger2;

/**
 * Pure-PHP arbitrary precision integer arithmetic library. Supports base-2, base-10, base-16, and base-256
 * numbers.
 *
 * @package BigInteger
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class BigInteger
{
    /**
     * The BigInteger object
     *
     * @var \phpseclib3\Math\BigInteger
     * @access private
     */
    private $bigint;

    /**
     * Converts base-2, base-10, base-16, and binary strings (base-256) to BigIntegers.
     *
     * If the second parameter - $base - is negative, then it will be assumed that the number's are encoded using
     * two's compliment.  The sole exception to this is -10, which is treated the same as 10 is.
     *
     * Here's an example:
     * <code>
     * <?php
     *    $a = new \phpseclib\Math\BigInteger('0x32', 16); // 50 in base-16
     *
     *    echo $a->toString(); // outputs 50
     * ?>
     * </code>
     *
     * @param $x base-10 number or base-$base number if $base set.
     * @param int $base
     * @return \phpseclib\Math\BigInteger
     * @access public
     */
    public function __construct()
    {
        $this->bigint = new BigInteger2;
    }

    /**
     *  __call() magic method
     *
     * @access public
     */
    public function __call($name, $args)
    {
        foreach ($args as &$arg) {
            if ($arg instanceof BigInteger2) {
                $arg = $arg->bigint;
            }
        }
        $result = $this->bigint->$name(...$args);
        if (!$result instanceof BigInteger2) {
            return $result;
        }

        $temp = new static;
        $temp->bigint = $result;

        return $temp;
    }

    /**
     * Generate a random number
     *
     * Returns a random number between $min and $max where $min and $max
     * can be defined using one of the two methods:
     *
     * $min->random($max)
     * $max->random($min)
     *
     * @param \phpseclib\Math\BigInteger $arg1
     * @param \phpseclib\Math\BigInteger $arg2
     * @return \phpseclib\Math\BigInteger
     * @access public
     * @internal The API for creating random numbers used to be $a->random($min, $max), where $a was a BigInteger object.
     *           That method is still supported for BC purposes.
     */
    public function random($arg1, $arg2 = false)
    {
        $temp = new static;
        $temp->bigint = BigInteger2::randomRange(
            $arg1->bigint,
            $arg2 instanceof BigInteger ? $arg2->bigint : $this->bigint
        );
        return $temp;
    }

    /**
     * Generate a random prime number.
     *
     * If there's not a prime within the given range, false will be returned.
     * If more than $timeout seconds have elapsed, give up and return false.
     *
     * @param \phpseclib\Math\BigInteger $arg1
     * @param \phpseclib\Math\BigInteger $arg2
     * @return Math_BigInteger|false
     * @access public
     * @internal See {@link http://www.cacr.math.uwaterloo.ca/hac/about/chap4.pdf#page=15 HAC 4.44}.
     */
    public function randomPrime($arg1, $arg2 = false)
    {
        $temp = new static;
        $temp->bigint = BigInteger2::randomRange(
            $arg1->bigint,
            $arg2 instanceof BigInteger ? $arg2->bigint : $this->bigint
        );
        return $temp;
    }
}