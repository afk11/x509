<?php

require "../vendor/autoload.php";


use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;

$curveName = 'secp256k1';
$sigAlg = new \Mdanter\X509\SignatureAlgorithm('sha512');
$math = \Mdanter\Ecc\EccFactory::getAdapter();
$f = new \Mdanter\X509\Factory();
$domain = $f->getDomain($math, $curveName, $sigAlg);

$issuerDetails = [
    "commonName" => "test ca"
];
$issuerSubject = new \Mdanter\X509\Certificates\CertificateSubject($issuerDetails);

$ca = $f->getCA($math, $domain, $issuerSubject);

print_r($ca);