package org.bc.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bc.util.Arrays;

public class DERObjectIdentifier extends ASN1Primitive {
   String identifier;
   private byte[] body;
   private static final long LONG_LIMIT = 72057594037927808L;
   private static ASN1ObjectIdentifier[][] cache = new ASN1ObjectIdentifier[256][];

   public static ASN1ObjectIdentifier getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof ASN1ObjectIdentifier)) {
         if (var0 instanceof DERObjectIdentifier) {
            return new ASN1ObjectIdentifier(((DERObjectIdentifier)var0).getId());
         } else if (var0 instanceof ASN1Encodable && ((ASN1Encodable)var0).toASN1Primitive() instanceof ASN1ObjectIdentifier) {
            return (ASN1ObjectIdentifier)((ASN1Encodable)var0).toASN1Primitive();
         } else if (var0 instanceof byte[]) {
            return ASN1ObjectIdentifier.fromOctetString((byte[])var0);
         } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + var0.getClass().getName());
         }
      } else {
         return (ASN1ObjectIdentifier)var0;
      }
   }

   public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject var0, boolean var1) {
      ASN1Primitive var2 = var0.getObject();
      return !var1 && !(var2 instanceof DERObjectIdentifier) ? ASN1ObjectIdentifier.fromOctetString(ASN1OctetString.getInstance(var0.getObject()).getOctets()) : getInstance(var2);
   }

   DERObjectIdentifier(byte[] var1) {
      StringBuffer var2 = new StringBuffer();
      long var3 = 0L;
      BigInteger var5 = null;
      boolean var6 = true;

      for(int var7 = 0; var7 != var1.length; ++var7) {
         int var8 = var1[var7] & 255;
         if (var3 <= 72057594037927808L) {
            var3 += (long)(var8 & 127);
            if ((var8 & 128) == 0) {
               if (var6) {
                  if (var3 < 40L) {
                     var2.append('0');
                  } else if (var3 < 80L) {
                     var2.append('1');
                     var3 -= 40L;
                  } else {
                     var2.append('2');
                     var3 -= 80L;
                  }

                  var6 = false;
               }

               var2.append('.');
               var2.append(var3);
               var3 = 0L;
            } else {
               var3 <<= 7;
            }
         } else {
            if (var5 == null) {
               var5 = BigInteger.valueOf(var3);
            }

            var5 = var5.or(BigInteger.valueOf((long)(var8 & 127)));
            if ((var8 & 128) == 0) {
               if (var6) {
                  var2.append('2');
                  var5 = var5.subtract(BigInteger.valueOf(80L));
                  var6 = false;
               }

               var2.append('.');
               var2.append(var5);
               var5 = null;
               var3 = 0L;
            } else {
               var5 = var5.shiftLeft(7);
            }
         }
      }

      this.identifier = var2.toString();
      this.body = Arrays.clone(var1);
   }

   public DERObjectIdentifier(String var1) {
      if (!isValidIdentifier(var1)) {
         throw new IllegalArgumentException("string " + var1 + " not an OID");
      } else {
         this.identifier = var1;
      }
   }

   public String getId() {
      return this.identifier;
   }

   private void writeField(ByteArrayOutputStream var1, long var2) {
      byte[] var4 = new byte[9];
      int var5 = 8;

      for(var4[var5] = (byte)((int)var2 & 127); var2 >= 128L; var4[var5] = (byte)((int)var2 & 127 | 128)) {
         var2 >>= 7;
         --var5;
      }

      var1.write(var4, var5, 9 - var5);
   }

   private void writeField(ByteArrayOutputStream var1, BigInteger var2) {
      int var3 = (var2.bitLength() + 6) / 7;
      if (var3 == 0) {
         var1.write(0);
      } else {
         BigInteger var4 = var2;
         byte[] var5 = new byte[var3];

         for(int var6 = var3 - 1; var6 >= 0; --var6) {
            var5[var6] = (byte)(var4.intValue() & 127 | 128);
            var4 = var4.shiftRight(7);
         }

         var5[var3 - 1] = (byte)(var5[var3 - 1] & 127);
         var1.write(var5, 0, var5.length);
      }

   }

   private void doOutput(ByteArrayOutputStream var1) {
      OIDTokenizer var2 = new OIDTokenizer(this.identifier);
      int var3 = Integer.parseInt(var2.nextToken()) * 40;
      String var4 = var2.nextToken();
      if (var4.length() <= 18) {
         this.writeField(var1, (long)var3 + Long.parseLong(var4));
      } else {
         this.writeField(var1, (new BigInteger(var4)).add(BigInteger.valueOf((long)var3)));
      }

      while(var2.hasMoreTokens()) {
         String var5 = var2.nextToken();
         if (var5.length() <= 18) {
            this.writeField(var1, Long.parseLong(var5));
         } else {
            this.writeField(var1, new BigInteger(var5));
         }
      }

   }

   protected synchronized byte[] getBody() {
      if (this.body == null) {
         ByteArrayOutputStream var1 = new ByteArrayOutputStream();
         this.doOutput(var1);
         this.body = var1.toByteArray();
      }

      return this.body;
   }

   boolean isConstructed() {
      return false;
   }

   int encodedLength() throws IOException {
      int var1 = this.getBody().length;
      return 1 + StreamUtil.calculateBodyLength(var1) + var1;
   }

   void encode(ASN1OutputStream var1) throws IOException {
      byte[] var2 = this.getBody();
      var1.write(6);
      var1.writeLength(var2.length);
      var1.write(var2);
   }

   public int hashCode() {
      return this.identifier.hashCode();
   }

   boolean asn1Equals(ASN1Primitive var1) {
      return !(var1 instanceof DERObjectIdentifier) ? false : this.identifier.equals(((DERObjectIdentifier)var1).identifier);
   }

   public String toString() {
      return this.getId();
   }

   private static boolean isValidIdentifier(String var0) {
      if (var0.length() >= 3 && var0.charAt(1) == '.') {
         char var1 = var0.charAt(0);
         if (var1 >= '0' && var1 <= '2') {
            boolean var2 = false;

            for(int var3 = var0.length() - 1; var3 >= 2; --var3) {
               char var4 = var0.charAt(var3);
               if ('0' <= var4 && var4 <= '9') {
                  var2 = true;
               } else {
                  if (var4 != '.') {
                     return false;
                  }

                  if (!var2) {
                     return false;
                  }

                  var2 = false;
               }
            }

            return var2;
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   static ASN1ObjectIdentifier fromOctetString(byte[] var0) {
      if (var0.length < 3) {
         return new ASN1ObjectIdentifier(var0);
      } else {
         int var1 = var0[var0.length - 2] & 255;
         int var2 = var0[var0.length - 1] & 127;
         ASN1ObjectIdentifier[][] var4 = cache;
         ASN1ObjectIdentifier var3;
         synchronized(cache) {
            ASN1ObjectIdentifier[] var5 = cache[var1];
            if (var5 == null) {
               var5 = cache[var1] = new ASN1ObjectIdentifier[128];
            }

            var3 = var5[var2];
            if (var3 == null) {
               return var5[var2] = new ASN1ObjectIdentifier(var0);
            }

            if (Arrays.areEqual(var0, var3.getBody())) {
               return var3;
            }

            var1 = var1 + 1 & 255;
            var5 = cache[var1];
            if (var5 == null) {
               var5 = cache[var1] = new ASN1ObjectIdentifier[128];
            }

            var3 = var5[var2];
            if (var3 == null) {
               return var5[var2] = new ASN1ObjectIdentifier(var0);
            }

            if (Arrays.areEqual(var0, var3.getBody())) {
               return var3;
            }

            var2 = var2 + 1 & 127;
            var3 = var5[var2];
            if (var3 == null) {
               return var5[var2] = new ASN1ObjectIdentifier(var0);
            }
         }

         return Arrays.areEqual(var0, var3.getBody()) ? var3 : new ASN1ObjectIdentifier(var0);
      }
   }
}
