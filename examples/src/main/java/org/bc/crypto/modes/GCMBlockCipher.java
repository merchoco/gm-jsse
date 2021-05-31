package org.bc.crypto.modes;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.modes.gcm.GCMExponentiator;
import org.bc.crypto.modes.gcm.GCMMultiplier;
import org.bc.crypto.modes.gcm.Tables1kGCMExponentiator;
import org.bc.crypto.modes.gcm.Tables8kGCMMultiplier;
import org.bc.crypto.params.AEADParameters;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.crypto.util.Pack;
import org.bc.util.Arrays;

public class GCMBlockCipher implements AEADBlockCipher {
   private static final int BLOCK_SIZE = 16;
   private BlockCipher cipher;
   private GCMMultiplier multiplier;
   private GCMExponentiator exp;
   private boolean forEncryption;
   private int macSize;
   private byte[] nonce;
   private byte[] initialAssociatedText;
   private byte[] H;
   private byte[] J0;
   private byte[] bufBlock;
   private byte[] macBlock;
   private byte[] S;
   private byte[] S_at;
   private byte[] S_atPre;
   private byte[] counter;
   private int bufOff;
   private long totalLength;
   private byte[] atBlock;
   private int atBlockPos;
   private long atLength;
   private long atLengthPre;

   public GCMBlockCipher(BlockCipher var1) {
      this(var1, (GCMMultiplier)null);
   }

   public GCMBlockCipher(BlockCipher var1, GCMMultiplier var2) {
      if (var1.getBlockSize() != 16) {
         throw new IllegalArgumentException("cipher required with a block size of 16.");
      } else {
         if (var2 == null) {
            var2 = new Tables8kGCMMultiplier();
         }

         this.cipher = var1;
         this.multiplier = (GCMMultiplier)var2;
      }
   }

   public BlockCipher getUnderlyingCipher() {
      return this.cipher;
   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName() + "/GCM";
   }

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      this.forEncryption = var1;
      this.macBlock = null;
      KeyParameter var3;
      if (var2 instanceof AEADParameters) {
         AEADParameters var4 = (AEADParameters)var2;
         this.nonce = var4.getNonce();
         this.initialAssociatedText = var4.getAssociatedText();
         int var5 = var4.getMacSize();
         if (var5 < 96 || var5 > 128 || var5 % 8 != 0) {
            throw new IllegalArgumentException("Invalid value for MAC size: " + var5);
         }

         this.macSize = var5 / 8;
         var3 = var4.getKey();
      } else {
         if (!(var2 instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("invalid parameters passed to GCM");
         }

         ParametersWithIV var6 = (ParametersWithIV)var2;
         this.nonce = var6.getIV();
         this.initialAssociatedText = null;
         this.macSize = 16;
         var3 = (KeyParameter)var6.getParameters();
      }

      int var7 = var1 ? 16 : 16 + this.macSize;
      this.bufBlock = new byte[var7];
      if (this.nonce != null && this.nonce.length >= 1) {
         if (var3 != null) {
            this.cipher.init(true, var3);
            this.H = new byte[16];
            this.cipher.processBlock(this.H, 0, this.H, 0);
            this.multiplier.init(this.H);
            this.exp = null;
         }

         this.J0 = new byte[16];
         if (this.nonce.length == 12) {
            System.arraycopy(this.nonce, 0, this.J0, 0, this.nonce.length);
            this.J0[15] = 1;
         } else {
            this.gHASH(this.J0, this.nonce, this.nonce.length);
            byte[] var8 = new byte[16];
            Pack.longToBigEndian((long)this.nonce.length * 8L, var8, 8);
            this.gHASHBlock(this.J0, var8);
         }

         this.S = new byte[16];
         this.S_at = new byte[16];
         this.S_atPre = new byte[16];
         this.atBlock = new byte[16];
         this.atBlockPos = 0;
         this.atLength = 0L;
         this.atLengthPre = 0L;
         this.counter = Arrays.clone(this.J0);
         this.bufOff = 0;
         this.totalLength = 0L;
         if (this.initialAssociatedText != null) {
            this.processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
         }

      } else {
         throw new IllegalArgumentException("IV must be at least 1 byte");
      }
   }

   public byte[] getMac() {
      return Arrays.clone(this.macBlock);
   }

   public int getOutputSize(int var1) {
      int var2 = var1 + this.bufOff;
      if (this.forEncryption) {
         return var2 + this.macSize;
      } else {
         return var2 < this.macSize ? 0 : var2 - this.macSize;
      }
   }

   public int getUpdateOutputSize(int var1) {
      int var2 = var1 + this.bufOff;
      if (!this.forEncryption) {
         if (var2 < this.macSize) {
            return 0;
         }

         var2 -= this.macSize;
      }

      return var2 - var2 % 16;
   }

   public void processAADByte(byte var1) {
      this.atBlock[this.atBlockPos] = var1;
      if (++this.atBlockPos == 16) {
         this.gHASHBlock(this.S_at, this.atBlock);
         this.atBlockPos = 0;
         this.atLength += 16L;
      }

   }

   public void processAADBytes(byte[] var1, int var2, int var3) {
      for(int var4 = 0; var4 < var3; ++var4) {
         this.atBlock[this.atBlockPos] = var1[var2 + var4];
         if (++this.atBlockPos == 16) {
            this.gHASHBlock(this.S_at, this.atBlock);
            this.atBlockPos = 0;
            this.atLength += 16L;
         }
      }

   }

   private void initCipher() {
      if (this.atLength > 0L) {
         System.arraycopy(this.S_at, 0, this.S_atPre, 0, 16);
         this.atLengthPre = this.atLength;
      }

      if (this.atBlockPos > 0) {
         this.gHASHPartial(this.S_atPre, this.atBlock, 0, this.atBlockPos);
         this.atLengthPre += (long)this.atBlockPos;
      }

      if (this.atLengthPre > 0L) {
         System.arraycopy(this.S_atPre, 0, this.S, 0, 16);
      }

   }

   public int processByte(byte var1, byte[] var2, int var3) throws DataLengthException {
      this.bufBlock[this.bufOff] = var1;
      if (++this.bufOff == this.bufBlock.length) {
         this.outputBlock(var2, var3);
         return 16;
      } else {
         return 0;
      }
   }

   public int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException {
      int var6 = 0;

      for(int var7 = 0; var7 < var3; ++var7) {
         this.bufBlock[this.bufOff] = var1[var2 + var7];
         if (++this.bufOff == this.bufBlock.length) {
            this.outputBlock(var4, var5 + var6);
            var6 += 16;
         }
      }

      return var6;
   }

   private void outputBlock(byte[] var1, int var2) {
      if (this.totalLength == 0L) {
         this.initCipher();
      }

      this.gCTRBlock(this.bufBlock, var1, var2);
      if (this.forEncryption) {
         this.bufOff = 0;
      } else {
         System.arraycopy(this.bufBlock, 16, this.bufBlock, 0, this.macSize);
         this.bufOff = this.macSize;
      }

   }

   public int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException {
      if (this.totalLength == 0L) {
         this.initCipher();
      }

      int var3 = this.bufOff;
      if (!this.forEncryption) {
         if (var3 < this.macSize) {
            throw new InvalidCipherTextException("data too short");
         }

         var3 -= this.macSize;
      }

      if (var3 > 0) {
         this.gCTRPartial(this.bufBlock, 0, var3, var1, var2);
      }

      this.atLength += (long)this.atBlockPos;
      if (this.atLength > this.atLengthPre) {
         if (this.atBlockPos > 0) {
            this.gHASHPartial(this.S_at, this.atBlock, 0, this.atBlockPos);
         }

         if (this.atLengthPre > 0L) {
            xor(this.S_at, this.S_atPre);
         }

         long var4 = this.totalLength * 8L + 127L >>> 7;
         byte[] var6 = new byte[16];
         if (this.exp == null) {
            this.exp = new Tables1kGCMExponentiator();
            this.exp.init(this.H);
         }

         this.exp.exponentiateX(var4, var6);
         multiply(this.S_at, var6);
         xor(this.S, this.S_at);
      }

      byte[] var8 = new byte[16];
      Pack.longToBigEndian(this.atLength * 8L, var8, 0);
      Pack.longToBigEndian(this.totalLength * 8L, var8, 8);
      this.gHASHBlock(this.S, var8);
      byte[] var5 = new byte[16];
      this.cipher.processBlock(this.J0, 0, var5, 0);
      xor(var5, this.S);
      int var9 = var3;
      this.macBlock = new byte[this.macSize];
      System.arraycopy(var5, 0, this.macBlock, 0, this.macSize);
      if (this.forEncryption) {
         System.arraycopy(this.macBlock, 0, var1, var2 + this.bufOff, this.macSize);
         var9 = var3 + this.macSize;
      } else {
         byte[] var7 = new byte[this.macSize];
         System.arraycopy(this.bufBlock, var3, var7, 0, this.macSize);
         if (!Arrays.constantTimeAreEqual(this.macBlock, var7)) {
            throw new InvalidCipherTextException("mac check in GCM failed");
         }
      }

      this.reset(false);
      return var9;
   }

   public void reset() {
      this.reset(true);
   }

   private void reset(boolean var1) {
      this.cipher.reset();
      this.S = new byte[16];
      this.S_at = new byte[16];
      this.S_atPre = new byte[16];
      this.atBlock = new byte[16];
      this.atBlockPos = 0;
      this.atLength = 0L;
      this.atLengthPre = 0L;
      this.counter = Arrays.clone(this.J0);
      this.bufOff = 0;
      this.totalLength = 0L;
      if (this.bufBlock != null) {
         Arrays.fill((byte[])this.bufBlock, (byte)0);
      }

      if (var1) {
         this.macBlock = null;
      }

      if (this.initialAssociatedText != null) {
         this.processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
      }

   }

   private void gCTRBlock(byte[] var1, byte[] var2, int var3) {
      byte[] var4 = this.getNextCounterBlock();
      xor(var4, var1);
      System.arraycopy(var4, 0, var2, var3, 16);
      this.gHASHBlock(this.S, this.forEncryption ? var4 : var1);
      this.totalLength += 16L;
   }

   private void gCTRPartial(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      byte[] var6 = this.getNextCounterBlock();
      xor(var6, var1, var2, var3);
      System.arraycopy(var6, 0, var4, var5, var3);
      this.gHASHPartial(this.S, this.forEncryption ? var6 : var1, 0, var3);
      this.totalLength += (long)var3;
   }

   private void gHASH(byte[] var1, byte[] var2, int var3) {
      for(int var4 = 0; var4 < var3; var4 += 16) {
         int var5 = Math.min(var3 - var4, 16);
         this.gHASHPartial(var1, var2, var4, var5);
      }

   }

   private void gHASHBlock(byte[] var1, byte[] var2) {
      xor(var1, var2);
      this.multiplier.multiplyH(var1);
   }

   private void gHASHPartial(byte[] var1, byte[] var2, int var3, int var4) {
      xor(var1, var2, var3, var4);
      this.multiplier.multiplyH(var1);
   }

   private byte[] getNextCounterBlock() {
      for(int var1 = 15; var1 >= 12; --var1) {
         byte var2 = (byte)(this.counter[var1] + 1 & 255);
         this.counter[var1] = var2;
         if (var2 != 0) {
            break;
         }
      }

      byte[] var3 = new byte[16];
      this.cipher.processBlock(this.counter, 0, var3, 0);
      return var3;
   }

   private static void multiply(byte[] var0, byte[] var1) {
      byte[] var2 = Arrays.clone(var0);
      byte[] var3 = new byte[16];

      for(int var4 = 0; var4 < 16; ++var4) {
         byte var5 = var1[var4];

         for(int var6 = 7; var6 >= 0; --var6) {
            if ((var5 & 1 << var6) != 0) {
               xor(var3, var2);
            }

            boolean var7 = (var2[15] & 1) != 0;
            shiftRight(var2);
            if (var7) {
               var2[0] ^= -31;
            }
         }
      }

      System.arraycopy(var3, 0, var0, 0, 16);
   }

   private static void shiftRight(byte[] var0) {
      int var1 = 0;
      int var2 = 0;

      while(true) {
         int var3 = var0[var1] & 255;
         var0[var1] = (byte)(var3 >>> 1 | var2);
         ++var1;
         if (var1 == 16) {
            return;
         }

         var2 = (var3 & 1) << 7;
      }
   }

   private static void xor(byte[] var0, byte[] var1) {
      for(int var2 = 15; var2 >= 0; --var2) {
         var0[var2] ^= var1[var2];
      }

   }

   private static void xor(byte[] var0, byte[] var1, int var2, int var3) {
      while(var3-- > 0) {
         var0[var3] ^= var1[var2 + var3];
      }

   }
}
