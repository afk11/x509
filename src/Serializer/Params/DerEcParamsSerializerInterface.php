<?php

namespace Mdanter\X509\Serializer\Params;


use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Primitives\GeneratorPoint;

interface DerEcParamsSerializerInterface
{
    /**
     * @param NamedCurveFp $curveFp
     * @param GeneratorPoint $generator
     * @return string
     */
    public function serialize(NamedCurveFp $curveFp, GeneratorPoint $generator);

    /**
     * @param string $string
     * @return NamedCurveFp
     */
    public function parse($string);

}