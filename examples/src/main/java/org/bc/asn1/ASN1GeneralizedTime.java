package org.bc.asn1;

import java.util.Date;

public class ASN1GeneralizedTime extends DERGeneralizedTime {
   ASN1GeneralizedTime(byte[] var1) {
      super(var1);
   }

   public ASN1GeneralizedTime(Date var1) {
      super(var1);
   }

   public ASN1GeneralizedTime(String var1) {
      super(var1);
   }
}
