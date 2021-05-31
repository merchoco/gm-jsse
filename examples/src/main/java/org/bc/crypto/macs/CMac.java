package org.bc.crypto.macs;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.Mac;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.paddings.ISO7816d4Padding;

public class CMac implements Mac {
   private static final byte CONSTANT_128 = -121;
   private static final byte CONSTANT_64 = 27;
   private byte[] ZEROES;
   private byte[] mac;
   private byte[] buf;
   private int bufOff;
   private BlockCipher cipher;
   private int macSize;
   private byte[] L;
   private byte[] Lu;
   private byte[] Lu2;

   public CMac(BlockCipher var1) {
      this(var1, var1.getBlockSize() * 8);
   }

   public CMac(BlockCipher var1, int var2) {
      if (var2 % 8 != 0) {
         throw new IllegalArgumentException("MAC size must be multiple of 8");
      } else if (var2 > var1.getBlockSize() * 8) {
         throw new IllegalArgumentException("MAC size must be less or equal to " + var1.getBlockSize() * 8);
      } else if (var1.getBlockSize() != 8 && var1.getBlockSize() != 16) {
         throw new IllegalArgumentException("Block size must be either 64 or 128 bits");
      } else {
         this.cipher = new CBCBlockCipher(var1);
         this.macSize = var2 / 8;
         this.mac = new byte[var1.getBlockSize()];
         this.buf = new byte[var1.getBlockSize()];
         this.ZEROES = new byte[var1.getBlockSize()];
         this.bufOff = 0;
      }
   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName();
   }

   private static byte[] doubleLu(byte[] var0) {
      int var1 = (var0[0] & 255) >> 7;
      byte[] var2 = new byte[var0.length];

      for(int var3 = 0; var3 < var0.length - 1; ++var3) {
         var2[var3] = (byte)((var0[var3] << 1) + ((var0[var3 + 1] & 255) >> 7));
      }

      var2[var0.length - 1] = (byte)(var0[var0.length - 1] << 1);
      if (var1 == 1) {
         var2[var0.length - 1] = (byte)(var2[var0.length - 1] ^ (var0.length == 16 ? -121 : 27));
      }

      return var2;
   }

   public void init(CipherParameters var1) {
      if (var1 != null) {
         this.cipher.init(true, var1);
         this.L = new byte[this.ZEROES.length];
         this.cipher.processBlock(this.ZEROES, 0, this.L, 0);
         this.Lu = doubleLu(this.L);
         this.Lu2 = doubleLu(this.Lu);
      }

      this.reset();
   }

   public int getMacSize() {
      return this.macSize;
   }

   public void update(byte var1) {
      if (this.bufOff == this.buf.length) {
         this.cipher.processBlock(this.buf, 0, this.mac, 0);
         this.bufOff = 0;
      }

      this.buf[this.bufOff++] = var1;
   }

   public void update(byte[] var1, int var2, int var3) {
      if (var3 < 0) {
         throw new IllegalArgumentException("Can't have a negative input length!");
      } else {
         int var4 = this.cipher.getBlockSize();
         int var5 = var4 - this.bufOff;
         if (var3 > var5) {
            System.arraycopy(var1, var2, this.buf, this.bufOff, var5);
            this.cipher.processBlock(this.buf, 0, this.mac, 0);
            this.bufOff = 0;
            var3 -= var5;

            for(var2 += var5; var3 > var4; var2 += var4) {
               this.cipher.processBlock(var1, var2, this.mac, 0);
               var3 -= var4;
            }
         }

         System.arraycopy(var1, var2, this.buf, this.bufOff, var3);
         this.bufOff += var3;
      }
   }

   public int doFinal(byte[] var1, int var2) {
      int var3 = this.cipher.getBlockSize();
      byte[] var4;
      if (this.bufOff == var3) {
         var4 = this.Lu;
      } else {
         (new ISO7816d4Padding()).addPadding(this.buf, this.bufOff);
         var4 = this.Lu2;
      }

      for(int var5 = 0; var5 < this.mac.length; ++var5) {
         this.buf[var5] ^= var4[var5];
      }

      this.cipher.processBlock(this.buf, 0, this.mac, 0);
      System.arraycopy(this.mac, 0, var1, var2, this.macSize);
      this.reset();
      return this.macSize;
   }

   public void reset() {
      for(int var1 = 0; var1 < this.buf.length; ++var1) {
         this.buf[var1] = 0;
      }

      this.bufOff = 0;
      this.cipher.reset();
   }
}
