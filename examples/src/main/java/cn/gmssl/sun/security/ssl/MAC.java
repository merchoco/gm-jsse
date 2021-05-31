package cn.gmssl.sun.security.ssl;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

final class MAC {
   static final MAC NULL = new MAC();
   private static final byte[] nullMAC = new byte[0];
   private final CipherSuite.MacAlg macAlg;
   private final int macSize;
   private final Mac mac;
   private final byte[] block;
   private static final int BLOCK_SIZE_SSL = 11;
   private static final int BLOCK_SIZE_TLS = 13;
   private static final int BLOCK_OFFSET_TYPE = 8;
   private static final int BLOCK_OFFSET_VERSION = 9;

   private MAC() {
      this.macSize = 0;
      this.macAlg = CipherSuite.M_NULL;
      this.mac = null;
      this.block = null;
   }

   MAC(CipherSuite.MacAlg var1, ProtocolVersion var2, SecretKey var3) throws NoSuchAlgorithmException, InvalidKeyException {
      this.macAlg = var1;
      this.macSize = var1.size;
      boolean var5 = var2.v >= ProtocolVersion.TLS10.v;
      String var4;
      if (var1 == CipherSuite.M_MD5) {
         var4 = var5 ? "HmacMD5" : "SslMacMD5";
      } else if (var1 == CipherSuite.M_SHA) {
         var4 = var5 ? "HmacSHA1" : "SslMacSHA1";
      } else if (var1 == CipherSuite.M_SM3) {
         var4 = "HmacSM3";
      } else if (var1 == CipherSuite.M_SHA256) {
         var4 = "HmacSHA256";
      } else {
         if (var1 != CipherSuite.M_SHA384) {
            throw new RuntimeException("Unknown Mac " + var1);
         }

         var4 = "HmacSHA384";
      }

      this.mac = JsseJce.getMac(var4);
      this.mac.init(var3);
      if (var5) {
         this.block = new byte[13];
         this.block[9] = var2.major;
         this.block[10] = var2.minor;
      } else {
         this.block = new byte[11];
      }

   }

   int MAClen() {
      return this.macSize;
   }

   final byte[] compute(byte var1, byte[] var2, int var3, int var4) {
      return this.compute(var1, (ByteBuffer)null, var2, var3, var4);
   }

   final byte[] compute(byte var1, ByteBuffer var2) {
      return this.compute(var1, var2, (byte[])null, 0, var2.remaining());
   }

   final boolean seqNumOverflow() {
      return this.block != null && this.mac != null && this.block[0] == 255 && this.block[1] == 255 && this.block[2] == 255 && this.block[3] == 255 && this.block[4] == 255 && this.block[5] == 255 && this.block[6] == 255;
   }

   final boolean seqNumIsHuge() {
      return this.block != null && this.mac != null && this.block[0] == 255 && this.block[1] == 255;
   }

   private void incrementSequenceNumber() {
      for(int var1 = 7; var1 >= 0 && ++this.block[var1] == 0; --var1) {
         ;
      }

   }

   private byte[] compute(byte var1, ByteBuffer var2, byte[] var3, int var4, int var5) {
      if (this.macSize == 0) {
         return nullMAC;
      } else {
         this.block[8] = var1;
         this.block[this.block.length - 2] = (byte)(var5 >> 8);
         this.block[this.block.length - 1] = (byte)var5;
         this.mac.update(this.block);
         this.incrementSequenceNumber();
         if (var2 != null) {
            this.mac.update(var2);
         } else {
            this.mac.update(var3, var4, var5);
         }

         return this.mac.doFinal();
      }
   }
}
