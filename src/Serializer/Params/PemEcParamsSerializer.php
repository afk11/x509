<?php

namespace Mdanter\X509\Serializer\Params;

use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\Primitives\GeneratorPoint;

/**
 * Serialize a named curve to it's explicit parameters.
 */
class PemEcParamsSerializer
{
    const VERSION = 3;
    const HEADER = '-----BEGIN EC PARAMETERS-----';
    const FOOTER = '-----END EC PARAMETERS-----';

    const FIELD_ID = '1.2.840.10045.1.1';

    /**
     * @var DerEcParamsSerializerInterface
     */
    private $serializer;

    /**
     * PemEcParamsSerializer constructor.
     * @param DerEcParamsSerializerInterface $serializer
     */
    public function __construct(DerEcParamsSerializerInterface $serializer)
    {
        $this->serializer = $serializer;
    }

    /**
     * @param NamedCurveFp $c
     * @param GeneratorPoint $G
     * @return string
     */
    public function serialize(NamedCurveFp $c, GeneratorPoint $G)
    {
        $payload = $this->serializer->serialize($c, $G);

        return sprintf("%s\n%s\n%s",
            self::HEADER,
            trim(chunk_split(base64_encode($payload), 64, PHP_EOL)),
            self::FOOTER
        );
    }

    /**
     * @param string $params
     * @return \Mdanter\Ecc\Curves\NamedCurveFp
     */
    public function parse($params)
    {
        $params = str_replace(self::HEADER, '', $params);
        $params = str_replace(self::FOOTER, '', $params);

        $binary = base64_decode($params);
        return $this->serializer->parse($binary);
    }
}
