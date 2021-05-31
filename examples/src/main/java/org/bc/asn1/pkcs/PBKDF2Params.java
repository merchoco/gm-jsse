package org.bc.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;

public class PBKDF2Params extends ASN1Object {
   private ASN1OctetString octStr;
   private ASN1Integer iterationCount;
   private ASN1Integer keyLength;

   public static PBKDF2Params getInstance(Object var0) {
      if (var0 instanceof PBKDF2Params) {
         return (PBKDF2Params)var0;
      } else {
         return var0 != null ? new PBKDF2Params(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public PBKDF2Params(byte[] var1, int var2) {
      this.octStr = new DEROctetString(var1);
      this.iterationCount = new ASN1Integer((long)var2);
   }

   public PBKDF2Params(byte[] var1, int var2, int var3) {
      this(var1, var2);
      this.keyLength = new ASN1Integer((long)var3);
   }

   private PBKDF2Params(ASN1Sequence var1) {
      Enumeration var2 = var1.getObjects();
      this.octStr = (ASN1OctetString)var2.nextElement();
      this.iterationCount = (ASN1Integer)var2.nextElement();
      if (var2.hasMoreElements()) {
         this.keyLength = (ASN1Integer)var2.nextElement();
      } else {
         this.keyLength = null;
      }

   }

   public byte[] getSalt() {
      return this.octStr.getOctets();
   }

   public BigInteger getIterationCount() {
      return this.iterationCount.getValue();
   }

   public BigInteger getKeyLength() {
      return this.keyLength != null ? this.keyLength.getValue() : null;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.octStr);
      var1.add(this.iterationCount);
      if (this.keyLength != null) {
         var1.add(this.keyLength);
      }

      return new DERSequence(var1);
   }
}
