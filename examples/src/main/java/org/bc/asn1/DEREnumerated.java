package org.bc.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.bc.util.Arrays;

public class DEREnumerated extends ASN1Primitive {
   byte[] bytes;
   private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

   public static ASN1Enumerated getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof ASN1Enumerated)) {
         if (var0 instanceof DEREnumerated) {
            return new ASN1Enumerated(((DEREnumerated)var0).getValue());
         } else if (var0 instanceof byte[]) {
            try {
               return (ASN1Enumerated)fromByteArray((byte[])var0);
            } catch (Exception var2) {
               throw new IllegalArgumentException("encoding error in getInstance: " + var2.toString());
            }
         } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + var0.getClass().getName());
         }
      } else {
         return (ASN1Enumerated)var0;
      }
   }

   public static DEREnumerated getInstance(ASN1TaggedObject var0, boolean var1) {
      ASN1Primitive var2 = var0.getObject();
      return !var1 && !(var2 instanceof DEREnumerated) ? fromOctetString(((ASN1OctetString)var2).getOctets()) : getInstance(var2);
   }

   public DEREnumerated(int var1) {
      this.bytes = BigInteger.valueOf((long)var1).toByteArray();
   }

   public DEREnumerated(BigInteger var1) {
      this.bytes = var1.toByteArray();
   }

   public DEREnumerated(byte[] var1) {
      this.bytes = var1;
   }

   public BigInteger getValue() {
      return new BigInteger(this.bytes);
   }

   boolean isConstructed() {
      return false;
   }

   int encodedLength() {
      return 1 + StreamUtil.calculateBodyLength(this.bytes.length) + this.bytes.length;
   }

   void encode(ASN1OutputStream var1) throws IOException {
      var1.writeEncoded(10, this.bytes);
   }

   boolean asn1Equals(ASN1Primitive var1) {
      if (!(var1 instanceof DEREnumerated)) {
         return false;
      } else {
         DEREnumerated var2 = (DEREnumerated)var1;
         return Arrays.areEqual(this.bytes, var2.bytes);
      }
   }

   public int hashCode() {
      return Arrays.hashCode(this.bytes);
   }

   static ASN1Enumerated fromOctetString(byte[] var0) {
      if (var0.length > 1) {
         return new ASN1Enumerated(Arrays.clone(var0));
      } else if (var0.length == 0) {
         throw new IllegalArgumentException("ENUMERATED has zero length");
      } else {
         int var1 = var0[0] & 255;
         if (var1 >= cache.length) {
            return new ASN1Enumerated(Arrays.clone(var0));
         } else {
            ASN1Enumerated var2 = cache[var1];
            if (var2 == null) {
               var2 = cache[var1] = new ASN1Enumerated(Arrays.clone(var0));
            }

            return var2;
         }
      }
   }
}
