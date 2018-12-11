<?php

namespace Mdanter\X509\Serializer\Params;

use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\OctetString;
use FG\ASN1\Universal\Sequence;
use Mdanter\Ecc\Curves\CurveRandomSeed;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;

/**
 * Serialize a named curve to it's explicit parameters.
 */
class DerEcParamsSerializer implements DerEcParamsSerializerInterface
{
    const VERSION = 3;
    const HEADER = '-----BEGIN EC PARAMETERS-----';
    const FOOTER = '-----END EC PARAMETERS-----';

    const FIELD_ID = '1.2.840.10045.1.1';
    
    /**
     * @var UncompressedPointSerializer
     */
    private $pointSerializer;
    
    /**
     * @param UncompressedPointSerializer $pointSerializer
     */
    public function __construct(UncompressedPointSerializer $pointSerializer)
    {
        $this->pointSerializer = $pointSerializer;
    }

    /**
     * @param NamedCurveFp $c
     * @return Sequence
     */
    private function getFieldIdAsn(NamedCurveFp $c)
    {
        return new Sequence(
            new ObjectIdentifier(self::FIELD_ID), // 1.2.840.10045.3.1.1.7
            new Integer(gmp_strval($c->getPrime(), 10))
        );
    }

    /**
     * @param GmpMathInterface $math
     * @param NamedCurveFp $c
     * @return Sequence
     */
    private function getCurveAsn(GmpMathInterface $math, NamedCurveFp $c)
    {
        $a = gmp_strval($math->mod($c->getA(), $c->getPrime()), 16);
        $a = strlen($a) % 2 === 0 ? $a : '0' . $a;

        $b = gmp_strval($math->mod($c->getB(), $c->getPrime()), 16);
        $b = strlen($b) % 2 === 0 ? $b : '0' . $b;

        try {
            $seed = CurveRandomSeed::getSeed($c);
            return new Sequence(
                new OctetString($a),
                new OctetString($b),
                new BitString($seed)
            );
        } catch (\Exception $e) {
            return new Sequence(
                new OctetString($a),
                new OctetString($b)
            );
        }
    }

    /**
     * @param NamedCurveFp $c
     * @param GeneratorPoint $G
     * @return string
     */
    public function serialize(NamedCurveFp $c, GeneratorPoint $G)
    {
        $math = $G->getAdapter();

        $fieldID = $this->getFieldIdAsn($c);
        $curve = $this->getCurveAsn($math, $c);

        $domain = new Sequence(
            new Integer(1),
            $fieldID,
            $curve,
            new OctetString($this->pointSerializer->serialize($G)),
            new Integer($G->getOrder()),
            new Integer(1)
        // Hash function oid ?
        );

        return $domain->getBinary();
    }

    /**
     * @param string $params
     * @return \Mdanter\Ecc\Curves\NamedCurveFp
     */
    public function parse($params)
    {
        $params = str_replace(self::HEADER, '', $params);
        $params = str_replace(self::FOOTER, '', $params);

        $oid = ObjectIdentifier::fromBinary(base64_decode($params));

        return CurveOidMapper::getCurveFromOid($oid);
    }
}
