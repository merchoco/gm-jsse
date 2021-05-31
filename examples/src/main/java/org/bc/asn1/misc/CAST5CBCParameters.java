package org.bc.asn1.misc;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;

public class CAST5CBCParameters extends ASN1Object {
   ASN1Integer keyLength;
   ASN1OctetString iv;

   public static CAST5CBCParameters getInstance(Object var0) {
      if (var0 instanceof CAST5CBCParameters) {
         return (CAST5CBCParameters)var0;
      } else {
         return var0 != null ? new CAST5CBCParameters(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public CAST5CBCParameters(byte[] var1, int var2) {
      this.iv = new DEROctetString(var1);
      this.keyLength = new ASN1Integer((long)var2);
   }

   public CAST5CBCParameters(ASN1Sequence var1) {
      this.iv = (ASN1OctetString)var1.getObjectAt(0);
      this.keyLength = (ASN1Integer)var1.getObjectAt(1);
   }

   public byte[] getIV() {
      return this.iv.getOctets();
   }

   public int getKeyLength() {
      return this.keyLength.getValue().intValue();
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.iv);
      var1.add(this.keyLength);
      return new DERSequence(var1);
   }
}
