<?php

namespace Mdanter\X509;

class SignatureAlgorithm
{
    /**
     * @var string
     */
    private $hashAlgo;

    /**
     * SignatureAlgorithm constructor.
     * @param string $hashAlgo
     */
    public function __construct($hashAlgo)
    {
        $this->hashAlgo = $hashAlgo;
    }

    /**
     * @return string
     */
    public function getHashAlgorithm()
    {
        return $this->hashAlgo;
    }

    /**
     * @return string
     */
    public function getEcdsaAlgorithm()
    {
        return "ecdsa+" . $this->hashAlgo;
    }
}
