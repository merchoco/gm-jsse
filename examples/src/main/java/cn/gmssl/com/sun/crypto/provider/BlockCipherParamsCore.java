package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import sun.misc.HexDumpEncoder;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;

final class BlockCipherParamsCore {
   private int block_size = 0;
   private byte[] iv = null;

   BlockCipherParamsCore(int var1) {
      this.block_size = var1;
   }

   void init(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof IvParameterSpec)) {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      } else {
         byte[] var2 = ((IvParameterSpec)var1).getIV();
         if (var2.length != this.block_size) {
            throw new InvalidParameterSpecException("IV not " + this.block_size + " bytes long");
         } else {
            this.iv = (byte[])var2.clone();
         }
      }
   }

   void init(byte[] var1) throws IOException {
      DerInputStream var2 = new DerInputStream(var1);
      byte[] var3 = var2.getOctetString();
      if (var2.available() != 0) {
         throw new IOException("IV parsing error: extra data");
      } else if (var3.length != this.block_size) {
         throw new IOException("IV not " + this.block_size + " bytes long");
      } else {
         this.iv = var3;
      }
   }

   void init(byte[] var1, String var2) throws IOException {
      if (var2 != null && !var2.equalsIgnoreCase("ASN.1")) {
         throw new IllegalArgumentException("Only support ASN.1 format");
      } else {
         this.init(var1);
      }
   }

   AlgorithmParameterSpec getParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (IvParameterSpec.class.isAssignableFrom(var1)) {
         return new IvParameterSpec(this.iv);
      } else {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      }
   }

   byte[] getEncoded() throws IOException {
      DerOutputStream var1 = new DerOutputStream();
      var1.putOctetString(this.iv);
      byte[] var2 = var1.toByteArray();
      var1.close();
      return var2;
   }

   byte[] getEncoded(String var1) throws IOException {
      return this.getEncoded();
   }

   public String toString() {
      String var1 = System.getProperty("line.separator");
      String var2 = var1 + "    iv:" + var1 + "[";
      HexDumpEncoder var3 = new HexDumpEncoder();
      var2 = var2 + var3.encodeBuffer(this.iv);
      var2 = var2 + "]" + var1;
      return var2;
   }
}
