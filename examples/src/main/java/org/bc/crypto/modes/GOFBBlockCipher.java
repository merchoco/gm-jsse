package org.bc.crypto.modes;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.ParametersWithIV;

public class GOFBBlockCipher implements BlockCipher {
   private byte[] IV;
   private byte[] ofbV;
   private byte[] ofbOutV;
   private final int blockSize;
   private final BlockCipher cipher;
   boolean firstStep = true;
   int N3;
   int N4;
   static final int C1 = 16843012;
   static final int C2 = 16843009;

   public GOFBBlockCipher(BlockCipher var1) {
      this.cipher = var1;
      this.blockSize = var1.getBlockSize();
      if (this.blockSize != 8) {
         throw new IllegalArgumentException("GCTR only for 64 bit block ciphers");
      } else {
         this.IV = new byte[var1.getBlockSize()];
         this.ofbV = new byte[var1.getBlockSize()];
         this.ofbOutV = new byte[var1.getBlockSize()];
      }
   }

   public BlockCipher getUnderlyingCipher() {
      return this.cipher;
   }

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      this.firstStep = true;
      this.N3 = 0;
      this.N4 = 0;
      if (var2 instanceof ParametersWithIV) {
         ParametersWithIV var3 = (ParametersWithIV)var2;
         byte[] var4 = var3.getIV();
         if (var4.length < this.IV.length) {
            System.arraycopy(var4, 0, this.IV, this.IV.length - var4.length, var4.length);

            for(int var5 = 0; var5 < this.IV.length - var4.length; ++var5) {
               this.IV[var5] = 0;
            }
         } else {
            System.arraycopy(var4, 0, this.IV, 0, this.IV.length);
         }

         this.reset();
         if (var3.getParameters() != null) {
            this.cipher.init(true, var3.getParameters());
         }
      } else {
         this.reset();
         if (var2 != null) {
            this.cipher.init(true, var2);
         }
      }

   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName() + "/GCTR";
   }

   public int getBlockSize() {
      return this.blockSize;
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) throws DataLengthException, IllegalStateException {
      if (var2 + this.blockSize > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var4 + this.blockSize > var3.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         if (this.firstStep) {
            this.firstStep = false;
            this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
            this.N3 = this.bytesToint(this.ofbOutV, 0);
            this.N4 = this.bytesToint(this.ofbOutV, 4);
         }

         this.N3 += 16843009;
         this.N4 += 16843012;
         this.intTobytes(this.N3, this.ofbV, 0);
         this.intTobytes(this.N4, this.ofbV, 4);
         this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);

         for(int var5 = 0; var5 < this.blockSize; ++var5) {
            var3[var4 + var5] = (byte)(this.ofbOutV[var5] ^ var1[var2 + var5]);
         }

         System.arraycopy(this.ofbV, this.blockSize, this.ofbV, 0, this.ofbV.length - this.blockSize);
         System.arraycopy(this.ofbOutV, 0, this.ofbV, this.ofbV.length - this.blockSize, this.blockSize);
         return this.blockSize;
      }
   }

   public void reset() {
      System.arraycopy(this.IV, 0, this.ofbV, 0, this.IV.length);
      this.cipher.reset();
   }

   private int bytesToint(byte[] var1, int var2) {
      return (var1[var2 + 3] << 24 & -16777216) + (var1[var2 + 2] << 16 & 16711680) + (var1[var2 + 1] << 8 & '\uff00') + (var1[var2] & 255);
   }

   private void intTobytes(int var1, byte[] var2, int var3) {
      var2[var3 + 3] = (byte)(var1 >>> 24);
      var2[var3 + 2] = (byte)(var1 >>> 16);
      var2[var3 + 1] = (byte)(var1 >>> 8);
      var2[var3] = (byte)var1;
   }
}