package org.bc.jce.interfaces;

import org.bc.jce.spec.GOST3410PublicKeyParameterSetSpec;

public interface GOST3410Params {
   String getPublicKeyParamSetOID();

   String getDigestParamSetOID();

   String getEncryptionParamSetOID();

   GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
}
