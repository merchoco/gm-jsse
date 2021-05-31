package org.bc.asn1;

import java.math.BigInteger;

public class ASN1Integer extends DERInteger {
   ASN1Integer(byte[] var1) {
      super(var1);
   }

   public ASN1Integer(BigInteger var1) {
      super(var1);
   }

   public ASN1Integer(long var1) {
      super(var1);
   }
}
