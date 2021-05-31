package org.bc.asn1.pkcs;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.x509.AlgorithmIdentifier;

public class KeyDerivationFunc extends AlgorithmIdentifier {
   KeyDerivationFunc(ASN1Sequence var1) {
      super(var1);
   }

   public KeyDerivationFunc(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      super(var1, var2);
   }
}
