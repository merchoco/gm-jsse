package org.bc.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.Digest;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.util.Arrays;

public class TlsBlockCipher implements TlsCipher {
   protected TlsClientContext context;
   protected byte[] randomData;
   protected BlockCipher encryptCipher;
   protected BlockCipher decryptCipher;
   protected TlsMac writeMac;
   protected TlsMac readMac;

   public TlsMac getWriteMac() {
      return this.writeMac;
   }

   public TlsMac getReadMac() {
      return this.readMac;
   }

   public TlsBlockCipher(TlsClientContext var1, BlockCipher var2, BlockCipher var3, Digest var4, Digest var5, int var6) {
      this.context = var1;
      this.randomData = new byte[256];
      var1.getSecureRandom().nextBytes(this.randomData);
      this.encryptCipher = var2;
      this.decryptCipher = var3;
      int var7 = 2 * var6 + var4.getDigestSize() + var5.getDigestSize() + var2.getBlockSize() + var3.getBlockSize();
      byte[] var8 = TlsUtils.calculateKeyBlock(var1, var7);
      byte var9 = 0;
      this.writeMac = new TlsMac(var1, var4, var8, var9, var4.getDigestSize());
      int var10 = var9 + var4.getDigestSize();
      this.readMac = new TlsMac(var1, var5, var8, var10, var5.getDigestSize());
      var10 += var5.getDigestSize();
      this.initCipher(true, var2, var8, var6, var10, var10 + var6 * 2);
      var10 += var6;
      this.initCipher(false, var3, var8, var6, var10, var10 + var6 + var2.getBlockSize());
   }

   protected void initCipher(boolean var1, BlockCipher var2, byte[] var3, int var4, int var5, int var6) {
      KeyParameter var7 = new KeyParameter(var3, var5, var4);
      ParametersWithIV var8 = new ParametersWithIV(var7, var3, var6, var2.getBlockSize());
      var2.init(var1, var8);
   }

   public byte[] encodePlaintext(short var1, byte[] var2, int var3, int var4) {
      int var5 = this.encryptCipher.getBlockSize();
      int var6 = var5 - 1 - (var4 + this.writeMac.getSize()) % var5;
      boolean var7 = this.context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      int var8;
      if (var7) {
         var8 = (255 - var6) / var5;
         int var9 = this.chooseExtraPadBlocks(this.context.getSecureRandom(), var8);
         var6 += var9 * var5;
      }

      var8 = var4 + this.writeMac.getSize() + var6 + 1;
      byte[] var13 = new byte[var8];
      System.arraycopy(var2, var3, var13, 0, var4);
      byte[] var10 = this.writeMac.calculateMac(var1, var2, var3, var4);
      System.arraycopy(var10, 0, var13, var4, var10.length);
      int var11 = var4 + var10.length;

      int var12;
      for(var12 = 0; var12 <= var6; ++var12) {
         var13[var12 + var11] = (byte)var6;
      }

      for(var12 = 0; var12 < var8; var12 += var5) {
         this.encryptCipher.processBlock(var13, var12, var13, var12);
      }

      return var13;
   }

   public byte[] decodeCiphertext(short var1, byte[] var2, int var3, int var4) throws IOException {
      int var5 = this.decryptCipher.getBlockSize();
      int var6 = this.readMac.getSize();
      int var7 = Math.max(var5, var6 + 1);
      if (var4 < var7) {
         throw new TlsFatalAlert((short)50);
      } else if (var4 % var5 != 0) {
         throw new TlsFatalAlert((short)21);
      } else {
         for(int var8 = 0; var8 < var4; var8 += var5) {
            this.decryptCipher.processBlock(var2, var3 + var8, var2, var3 + var8);
         }

         int var9 = this.checkPaddingConstantTime(var2, var3, var4, var5, var6);
         int var10 = var4 - var9 - var6;
         byte[] var11 = Arrays.copyOfRange(var2, var3 + var10, var3 + var10 + var6);
         byte[] var12 = this.readMac.calculateMacConstantTime(var1, var2, var3, var10, var4 - var6, this.randomData);
         boolean var13 = !Arrays.constantTimeAreEqual(var12, var11);
         if (!var13 && var9 != 0) {
            return Arrays.copyOfRange(var2, var3, var3 + var10);
         } else {
            throw new TlsFatalAlert((short)20);
         }
      }
   }

   protected int checkPaddingConstantTime(byte[] var1, int var2, int var3, int var4, int var5) {
      int var6 = var2 + var3;
      byte var7 = var1[var6 - 1];
      int var8 = var7 & 255;
      int var9 = var8 + 1;
      int var10 = 0;
      byte var11 = 0;
      boolean var12 = this.context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
      if ((var12 || var9 <= var4) && var5 + var9 <= var3) {
         int var13 = var6 - var9;

         do {
            var11 = (byte)(var11 | var1[var13++] ^ var7);
         } while(var13 < var6);

         var10 = var9;
         if (var11 != 0) {
            var9 = 0;
         }
      } else {
         var9 = 0;
      }

      byte[] var14;
      for(var14 = this.randomData; var10 < 256; var11 = (byte)(var11 | var14[var10++] ^ var7)) {
         ;
      }

      var14[0] ^= var11;
      return var9;
   }

   protected int chooseExtraPadBlocks(SecureRandom var1, int var2) {
      int var3 = var1.nextInt();
      int var4 = this.lowestBitSet(var3);
      return Math.min(var4, var2);
   }

   protected int lowestBitSet(int var1) {
      if (var1 == 0) {
         return 32;
      } else {
         int var2;
         for(var2 = 0; (var1 & 1) == 0; var1 >>= 1) {
            ++var2;
         }

         return var2;
      }
   }
}
