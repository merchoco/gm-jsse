package org.bc.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.bc.util.Arrays;

public class DERApplicationSpecific extends ASN1Primitive {
   private final boolean isConstructed;
   private final int tag;
   private final byte[] octets;

   DERApplicationSpecific(boolean var1, int var2, byte[] var3) {
      this.isConstructed = var1;
      this.tag = var2;
      this.octets = var3;
   }

   public DERApplicationSpecific(int var1, byte[] var2) {
      this(false, var1, var2);
   }

   public DERApplicationSpecific(int var1, ASN1Encodable var2) throws IOException {
      this(true, var1, var2);
   }

   public DERApplicationSpecific(boolean var1, int var2, ASN1Encodable var3) throws IOException {
      ASN1Primitive var4 = var3.toASN1Primitive();
      byte[] var5 = var4.getEncoded("DER");
      this.isConstructed = var1 || var4 instanceof ASN1Set || var4 instanceof ASN1Sequence;
      this.tag = var2;
      if (var1) {
         this.octets = var5;
      } else {
         int var6 = this.getLengthOfHeader(var5);
         byte[] var7 = new byte[var5.length - var6];
         System.arraycopy(var5, var6, var7, 0, var7.length);
         this.octets = var7;
      }

   }

   public DERApplicationSpecific(int var1, ASN1EncodableVector var2) {
      this.tag = var1;
      this.isConstructed = true;
      ByteArrayOutputStream var3 = new ByteArrayOutputStream();

      for(int var4 = 0; var4 != var2.size(); ++var4) {
         try {
            var3.write(((ASN1Object)var2.get(var4)).getEncoded("DER"));
         } catch (IOException var6) {
            throw new ASN1ParsingException("malformed object: " + var6, var6);
         }
      }

      this.octets = var3.toByteArray();
   }

   public static DERApplicationSpecific getInstance(Object var0) {
      if (var0 != null && !(var0 instanceof DERApplicationSpecific)) {
         if (var0 instanceof byte[]) {
            try {
               return getInstance(ASN1Primitive.fromByteArray((byte[])var0));
            } catch (IOException var2) {
               throw new IllegalArgumentException("failed to construct object from byte[]: " + var2.getMessage());
            }
         } else {
            if (var0 instanceof ASN1Encodable) {
               ASN1Primitive var1 = ((ASN1Encodable)var0).toASN1Primitive();
               if (var1 instanceof ASN1Sequence) {
                  return (DERApplicationSpecific)var1;
               }
            }

            throw new IllegalArgumentException("unknown object in getInstance: " + var0.getClass().getName());
         }
      } else {
         return (DERApplicationSpecific)var0;
      }
   }

   private int getLengthOfHeader(byte[] var1) {
      int var2 = var1[1] & 255;
      if (var2 == 128) {
         return 2;
      } else if (var2 > 127) {
         int var3 = var2 & 127;
         if (var3 > 4) {
            throw new IllegalStateException("DER length more than 4 bytes: " + var3);
         } else {
            return var3 + 2;
         }
      } else {
         return 2;
      }
   }

   public boolean isConstructed() {
      return this.isConstructed;
   }

   public byte[] getContents() {
      return this.octets;
   }

   public int getApplicationTag() {
      return this.tag;
   }

   public ASN1Primitive getObject() throws IOException {
      return (new ASN1InputStream(this.getContents())).readObject();
   }

   public ASN1Primitive getObject(int var1) throws IOException {
      if (var1 >= 31) {
         throw new IOException("unsupported tag number");
      } else {
         byte[] var2 = this.getEncoded();
         byte[] var3 = this.replaceTagNumber(var1, var2);
         if ((var2[0] & 32) != 0) {
            var3[0] = (byte)(var3[0] | 32);
         }

         return (new ASN1InputStream(var3)).readObject();
      }
   }

   int encodedLength() throws IOException {
      return StreamUtil.calculateTagLength(this.tag) + StreamUtil.calculateBodyLength(this.octets.length) + this.octets.length;
   }

   void encode(ASN1OutputStream var1) throws IOException {
      int var2 = 64;
      if (this.isConstructed) {
         var2 |= 32;
      }

      var1.writeEncoded(var2, this.tag, this.octets);
   }

   boolean asn1Equals(ASN1Primitive var1) {
      if (!(var1 instanceof DERApplicationSpecific)) {
         return false;
      } else {
         DERApplicationSpecific var2 = (DERApplicationSpecific)var1;
         return this.isConstructed == var2.isConstructed && this.tag == var2.tag && Arrays.areEqual(this.octets, var2.octets);
      }
   }

   public int hashCode() {
      return (this.isConstructed ? 1 : 0) ^ this.tag ^ Arrays.hashCode(this.octets);
   }

   private byte[] replaceTagNumber(int var1, byte[] var2) throws IOException {
      int var3 = var2[0] & 31;
      int var4 = 1;
      if (var3 == 31) {
         var3 = 0;
         int var5 = var2[var4++] & 255;
         if ((var5 & 127) == 0) {
            throw new ASN1ParsingException("corrupted stream - invalid high tag number found");
         }

         while(var5 >= 0 && (var5 & 128) != 0) {
            var3 |= var5 & 127;
            var3 <<= 7;
            var5 = var2[var4++] & 255;
         }

         int var10000 = var3 | var5 & 127;
      }

      byte[] var6 = new byte[var2.length - var4 + 1];
      System.arraycopy(var2, var4, var6, 1, var6.length - 1);
      var6[0] = (byte)var1;
      return var6;
   }
}
