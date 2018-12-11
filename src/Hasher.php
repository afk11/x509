<?php

namespace Mdanter\X509;

class Hasher
{
    /**
     * @var string
     */
    private $algo;

    /**
     * @param string $algo
     * @internal param MathAdapterInterface $math
     */
    public function __construct($algo)
    {
        if (!in_array($algo, hash_algos())) {
            throw new \InvalidArgumentException('Hashing algorithm not known');
        }

        $this->algo = $algo;
    }

    /**
     * @return string
     */
    public function getAlgo()
    {
        return $this->algo;
    }

    /**
     * @param $string - a binary string to hash
     * @param bool|false $binary
     * @return string
     */
    public function hash($string, $binary = false)
    {
        return hash($this->algo, $string, $binary);
    }
    /**
     * Hash the data, returning a decimal.
     *
     * @param $string - a binary string to hash
     * @return \GMP
     */
    public function hashGmp($string)
    {
        return gmp_init($this->hash($string, false), 16);
    }
    /**
     * Hash the data, returning a decimal.
     *
     * @param $string - a binary string to hash
     * @return int|string
     */
    public function hashDec($string)
    {
        $hex = unpack("H*", $this->hash($string, false))[1];
        return gmp_strval(gmp_init($hex, 16), 10);
    }
}
