package org.bc.asn1.pkcs;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.DigestInfo;

public class MacData extends ASN1Object {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   DigestInfo digInfo;
   byte[] salt;
   BigInteger iterationCount;

   public static MacData getInstance(Object var0) {
      if (var0 instanceof MacData) {
         return (MacData)var0;
      } else {
         return var0 != null ? new MacData(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private MacData(ASN1Sequence var1) {
      this.digInfo = DigestInfo.getInstance(var1.getObjectAt(0));
      this.salt = ((ASN1OctetString)var1.getObjectAt(1)).getOctets();
      if (var1.size() == 3) {
         this.iterationCount = ((ASN1Integer)var1.getObjectAt(2)).getValue();
      } else {
         this.iterationCount = ONE;
      }

   }

   public MacData(DigestInfo var1, byte[] var2, int var3) {
      this.digInfo = var1;
      this.salt = var2;
      this.iterationCount = BigInteger.valueOf((long)var3);
   }

   public DigestInfo getMac() {
      return this.digInfo;
   }

   public byte[] getSalt() {
      return this.salt;
   }

   public BigInteger getIterationCount() {
      return this.iterationCount;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.digInfo);
      var1.add(new DEROctetString(this.salt));
      if (!this.iterationCount.equals(ONE)) {
         var1.add(new ASN1Integer(this.iterationCount));
      }

      return new DERSequence(var1);
   }
}
