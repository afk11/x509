<?php

namespace Mdanter\X509\Serializer\Params;

use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use FG\ASN1\Universal\ObjectIdentifier;

class DerEcParamsOidSerializer implements DerEcParamsSerializerInterface
{
    const HEADER = '-----BEGIN EC PARAMETERS-----';
    const FOOTER = '-----END EC PARAMETERS-----';

    /**
     * @param NamedCurveFp $c
     * @param GeneratorPoint $G
     * @return string
     */
    public function serialize(NamedCurveFp $c, GeneratorPoint $G)
    {
        $oid = CurveOidMapper::getCurveOid($c);
        return $oid->getBinary();
    }

    /**
     * @param string $params
     * @return \Mdanter\Ecc\Curves\NamedCurveFp
     */
    public function parse($params)
    {
        $oid = ObjectIdentifier::fromBinary(base64_decode($params));
        return CurveOidMapper::getCurveFromOid($oid);
    }
}
