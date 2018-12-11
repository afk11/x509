<?php

namespace Mdanter\X509;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\X509\Certificates\CertificateAuthority;
use Mdanter\X509\Certificates\CertificateSubject;
use Mdanter\X509\Certificates\Csr;

class Factory
{
    /**
     * @param GmpMathInterface $adapter
     * @param string $curveName
     * @param SignatureAlgorithm $sigAlgorithm
     * @return EcDomain
     */
    public static function getDomain(GmpMathInterface $adapter, $curveName, SignatureAlgorithm $sigAlgorithm)
    {
        $adapter = $adapter ?: EccFactory::getAdapter();

        return new EcDomain(
            $adapter,
            CurveFactory::getCurveByName($curveName),
            CurveFactory::getGeneratorByName($curveName),
            $sigAlgorithm
        );
    }

    /**
     * @param EcDomain $domain
     * @param CertificateSubject $subject
     * @param PrivateKeyInterface $privateKey
     * @return Csr
     */
    public static function getCsr(EcDomain $domain, CertificateSubject $subject, PrivateKeyInterface $privateKey)
    {
        $subjectSerializer = new CertificateSubjectSerializer();
        $serialized = $subjectSerializer->serialize($subject);
        $hash = $domain->getHasher()->hashGmp($serialized);

        return new Csr(
            $domain,
            $subject,
            $privateKey->getPublicKey(),
            $domain
                ->getSigner()
                ->sign(
                    $privateKey,
                    $hash,
                    RandomGeneratorFactory::getRandomGenerator()
                        ->generate($domain->getGenerator()->getOrder())
                )
        );
    }

    /**
     * @param GmpMathInterface $math
     * @param EcDomain $domain
     * @param CertificateSubject $issuerSubject
     * @return CertificateAuthority
     */
    public static function getCA(GmpMathInterface $math, EcDomain $domain, CertificateSubject $issuerSubject)
    {
        return new CertificateAuthority(
            $math,
            $domain,
            $issuerSubject
        );
    }
}
