package org.bc.asn1;

import java.math.BigInteger;

public class ASN1Enumerated extends DEREnumerated {
   ASN1Enumerated(byte[] var1) {
      super(var1);
   }

   public ASN1Enumerated(BigInteger var1) {
      super(var1);
   }

   public ASN1Enumerated(int var1) {
      super(var1);
   }
}
