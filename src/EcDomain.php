<?php

namespace Mdanter\X509;

use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;

class EcDomain
{
    /**
     * @var NamedCurveFp
     */
    private $curve;

    /**
     * @var GeneratorPoint
     */
    private $generator;

    /**
     * @var Hasher
     */
    private $hasher;

    /**
     * @var GmpMathInterface
     */
    private $math;

    /**
     * @var SignatureAlgorithm
     */
    private $sigAlg;

    /**
     * EcDomain constructor.
     * @param GmpMathInterface $math
     * @param NamedCurveFp $curve
     * @param GeneratorPoint $generatorPoint
     * @param SignatureAlgorithm $sigAlg
     */
    public function __construct(GmpMathInterface $math, NamedCurveFp $curve, GeneratorPoint $generatorPoint, SignatureAlgorithm $sigAlg)
    {
        if (!$curve->contains($generatorPoint->getX(), $generatorPoint->getY())) {
            throw new \RuntimeException('Provided generator point does not exist on curve');
        }

        $this->sigAlg = $sigAlg;
        $this->curve = $curve;
        $this->generator = $generatorPoint;
        $this->math = $math;
        $this->hasher = new Hasher($sigAlg->getHashAlgorithm());
        $this->signer = new Signer($math);
    }

    /**
     * @return NamedCurveFp
     */
    public function getCurve()
    {
        return $this->curve;
    }

    /**
     * @return GeneratorPoint
     */
    public function getGenerator()
    {
        return $this->generator;
    }

    /**
     * @return SignatureAlgorithm
     */
    public function getSigAlgorithm()
    {
        return $this->sigAlg;
    }

    /**
     * @return Hasher
     */
    public function getHasher()
    {
        return $this->hasher;
    }

    /**
     * @return Signer
     */
    public function getSigner()
    {
        return new Signer($this->math);
    }
}
