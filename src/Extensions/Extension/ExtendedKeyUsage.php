<?php

namespace Mdanter\X509\Extensions\Extension;

use Mdanter\X509\Extensions\MultiValuedExtension;

class ExtendedKeyUsage extends MultiValuedExtension
{
    public function __construct($critical)
    {
        parent::__construct($critical);
    }

    public function addKeyPurpose()
    {

    }
}
