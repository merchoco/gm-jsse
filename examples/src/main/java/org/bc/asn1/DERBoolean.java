package org.bc.asn1;

import java.io.IOException;
import org.bc.util.Arrays;

public class DERBoolean extends ASN1Primitive {
   private static final byte[] TRUE_VALUE = new byte[]{-1};
   private static final byte[] FALSE_VALUE = new byte[1];
   private byte[] value;
   public static final ASN1Boolean FALSE = new ASN1Boolean(false);
   public static final ASN1Boolean TRUE = new ASN1Boolean(true);

   public static ASN1Boolean getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof ASN1Boolean)) {
         if (var0 instanceof DERBoolean) {
            return ((DERBoolean)var0).isTrue() ? TRUE : FALSE;
         } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + var0.getClass().getName());
         }
      } else {
         return (ASN1Boolean)var0;
      }
   }

   public static ASN1Boolean getInstance(boolean var0) {
      return var0 ? TRUE : FALSE;
   }

   public static ASN1Boolean getInstance(int var0) {
      return var0 != 0 ? TRUE : FALSE;
   }

   public static DERBoolean getInstance(ASN1TaggedObject var0, boolean var1) {
      ASN1Primitive var2 = var0.getObject();
      return !var1 && !(var2 instanceof DERBoolean) ? ASN1Boolean.fromOctetString(((ASN1OctetString)var2).getOctets()) : getInstance(var2);
   }

   DERBoolean(byte[] var1) {
      if (var1.length != 1) {
         throw new IllegalArgumentException("byte value should have 1 byte in it");
      } else {
         if (var1[0] == 0) {
            this.value = FALSE_VALUE;
         } else if (var1[0] == 255) {
            this.value = TRUE_VALUE;
         } else {
            this.value = Arrays.clone(var1);
         }

      }
   }

   /** @deprecated */
   public DERBoolean(boolean var1) {
      this.value = var1 ? TRUE_VALUE : FALSE_VALUE;
   }

   public boolean isTrue() {
      return this.value[0] != 0;
   }

   boolean isConstructed() {
      return false;
   }

   int encodedLength() {
      return 3;
   }

   void encode(ASN1OutputStream var1) throws IOException {
      var1.writeEncoded(1, this.value);
   }

   protected boolean asn1Equals(ASN1Primitive var1) {
      if (var1 != null && var1 instanceof DERBoolean) {
         return this.value[0] == ((DERBoolean)var1).value[0];
      } else {
         return false;
      }
   }

   public int hashCode() {
      return this.value[0];
   }

   public String toString() {
      return this.value[0] != 0 ? "TRUE" : "FALSE";
   }

   static ASN1Boolean fromOctetString(byte[] var0) {
      if (var0.length != 1) {
         throw new IllegalArgumentException("byte value should have 1 byte in it");
      } else if (var0[0] == 0) {
         return FALSE;
      } else {
         return var0[0] == 255 ? TRUE : new ASN1Boolean(var0);
      }
   }
}
