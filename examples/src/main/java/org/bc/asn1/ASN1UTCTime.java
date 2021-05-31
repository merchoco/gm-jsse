package org.bc.asn1;

import java.util.Date;

public class ASN1UTCTime extends DERUTCTime {
   ASN1UTCTime(byte[] var1) {
      super(var1);
   }

   public ASN1UTCTime(Date var1) {
      super(var1);
   }

   public ASN1UTCTime(String var1) {
      super(var1);
   }
}
