package org.bc.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.bc.util.Arrays;

public class DERInteger extends ASN1Primitive {
   byte[] bytes;

   public static ASN1Integer getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof ASN1Integer)) {
         if (var0 instanceof DERInteger) {
            return new ASN1Integer(((DERInteger)var0).getValue());
         } else if (var0 instanceof byte[]) {
            try {
               return (ASN1Integer)fromByteArray((byte[])var0);
            } catch (Exception var2) {
               throw new IllegalArgumentException("encoding error in getInstance: " + var2.toString());
            }
         } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + var0.getClass().getName());
         }
      } else {
         return (ASN1Integer)var0;
      }
   }

   public static ASN1Integer getInstance(ASN1TaggedObject var0, boolean var1) {
      ASN1Primitive var2 = var0.getObject();
      return !var1 && !(var2 instanceof DERInteger) ? new ASN1Integer(ASN1OctetString.getInstance(var0.getObject()).getOctets()) : getInstance(var2);
   }

   public DERInteger(long var1) {
      this.bytes = BigInteger.valueOf(var1).toByteArray();
   }

   public DERInteger(BigInteger var1) {
      this.bytes = var1.toByteArray();
   }

   public DERInteger(byte[] var1) {
      this.bytes = var1;
   }

   public BigInteger getValue() {
      return new BigInteger(this.bytes);
   }

   public BigInteger getPositiveValue() {
      return new BigInteger(1, this.bytes);
   }

   boolean isConstructed() {
      return false;
   }

   int encodedLength() {
      return 1 + StreamUtil.calculateBodyLength(this.bytes.length) + this.bytes.length;
   }

   void encode(ASN1OutputStream var1) throws IOException {
      var1.writeEncoded(2, this.bytes);
   }

   public int hashCode() {
      int var1 = 0;

      for(int var2 = 0; var2 != this.bytes.length; ++var2) {
         var1 ^= (this.bytes[var2] & 255) << var2 % 4;
      }

      return var1;
   }

   boolean asn1Equals(ASN1Primitive var1) {
      if (!(var1 instanceof DERInteger)) {
         return false;
      } else {
         DERInteger var2 = (DERInteger)var1;
         return Arrays.areEqual(this.bytes, var2.bytes);
      }
   }

   public String toString() {
      return this.getValue().toString();
   }
}
