package org.bc.crypto.modes;

import java.io.ByteArrayOutputStream;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.macs.CBCBlockCipherMac;
import org.bc.crypto.params.AEADParameters;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.util.Arrays;

public class CCMBlockCipher implements AEADBlockCipher {
   private BlockCipher cipher;
   private int blockSize;
   private boolean forEncryption;
   private byte[] nonce;
   private byte[] initialAssociatedText;
   private int macSize;
   private CipherParameters keyParam;
   private byte[] macBlock;
   private ByteArrayOutputStream associatedText = new ByteArrayOutputStream();
   private ByteArrayOutputStream data = new ByteArrayOutputStream();

   public CCMBlockCipher(BlockCipher var1) {
      this.cipher = var1;
      this.blockSize = var1.getBlockSize();
      this.macBlock = new byte[this.blockSize];
      if (this.blockSize != 16) {
         throw new IllegalArgumentException("cipher required with a block size of 16.");
      }
   }

   public BlockCipher getUnderlyingCipher() {
      return this.cipher;
   }

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      this.forEncryption = var1;
      if (var2 instanceof AEADParameters) {
         AEADParameters var3 = (AEADParameters)var2;
         this.nonce = var3.getNonce();
         this.initialAssociatedText = var3.getAssociatedText();
         this.macSize = var3.getMacSize() / 8;
         this.keyParam = var3.getKey();
      } else {
         if (!(var2 instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("invalid parameters passed to CCM");
         }

         ParametersWithIV var4 = (ParametersWithIV)var2;
         this.nonce = var4.getIV();
         this.initialAssociatedText = null;
         this.macSize = this.macBlock.length / 2;
         this.keyParam = var4.getParameters();
      }

   }

   public String getAlgorithmName() {
      return this.cipher.getAlgorithmName() + "/CCM";
   }

   public void processAADByte(byte var1) {
      this.associatedText.write(var1);
   }

   public void processAADBytes(byte[] var1, int var2, int var3) {
      this.associatedText.write(var1, var2, var3);
   }

   public int processByte(byte var1, byte[] var2, int var3) throws DataLengthException, IllegalStateException {
      this.data.write(var1);
      return 0;
   }

   public int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException, IllegalStateException {
      this.data.write(var1, var2, var3);
      return 0;
   }

   public int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException {
      byte[] var3 = this.data.toByteArray();
      byte[] var4 = this.processPacket(var3, 0, var3.length);
      System.arraycopy(var4, 0, var1, var2, var4.length);
      this.reset();
      return var4.length;
   }

   public void reset() {
      this.cipher.reset();
      this.associatedText.reset();
      this.data.reset();
   }

   public byte[] getMac() {
      byte[] var1 = new byte[this.macSize];
      System.arraycopy(this.macBlock, 0, var1, 0, var1.length);
      return var1;
   }

   public int getUpdateOutputSize(int var1) {
      return 0;
   }

   public int getOutputSize(int var1) {
      int var2 = var1 + this.data.size();
      if (this.forEncryption) {
         return var2 + this.macSize;
      } else {
         return var2 < this.macSize ? 0 : var2 - this.macSize;
      }
   }

   public byte[] processPacket(byte[] var1, int var2, int var3) throws IllegalStateException, InvalidCipherTextException {
      if (this.keyParam == null) {
         throw new IllegalStateException("CCM cipher unitialized.");
      } else {
         SICBlockCipher var4 = new SICBlockCipher(this.cipher);
         byte[] var5 = new byte[this.blockSize];
         var5[0] = (byte)(15 - this.nonce.length - 1 & 7);
         System.arraycopy(this.nonce, 0, var5, 1, this.nonce.length);
         var4.init(this.forEncryption, new ParametersWithIV(this.keyParam, var5));
         byte[] var6;
         int var7;
         int var8;
         byte[] var9;
         if (this.forEncryption) {
            var7 = var2;
            var8 = 0;
            var6 = new byte[var3 + this.macSize];
            this.calculateMac(var1, var2, var3, this.macBlock);
            var4.processBlock(this.macBlock, 0, this.macBlock, 0);

            while(var7 < var3 - this.blockSize) {
               var4.processBlock(var1, var7, var6, var8);
               var8 += this.blockSize;
               var7 += this.blockSize;
            }

            var9 = new byte[this.blockSize];
            System.arraycopy(var1, var7, var9, 0, var3 - var7);
            var4.processBlock(var9, 0, var9, 0);
            System.arraycopy(var9, 0, var6, var8, var3 - var7);
            var8 += var3 - var7;
            System.arraycopy(this.macBlock, 0, var6, var8, var6.length - var8);
         } else {
            var7 = var2;
            var8 = 0;
            var6 = new byte[var3 - this.macSize];
            System.arraycopy(var1, var2 + var3 - this.macSize, this.macBlock, 0, this.macSize);
            var4.processBlock(this.macBlock, 0, this.macBlock, 0);

            for(int var11 = this.macSize; var11 != this.macBlock.length; ++var11) {
               this.macBlock[var11] = 0;
            }

            while(var8 < var6.length - this.blockSize) {
               var4.processBlock(var1, var7, var6, var8);
               var8 += this.blockSize;
               var7 += this.blockSize;
            }

            var9 = new byte[this.blockSize];
            System.arraycopy(var1, var7, var9, 0, var6.length - var8);
            var4.processBlock(var9, 0, var9, 0);
            System.arraycopy(var9, 0, var6, var8, var6.length - var8);
            byte[] var10 = new byte[this.blockSize];
            this.calculateMac(var6, 0, var6.length, var10);
            if (!Arrays.constantTimeAreEqual(this.macBlock, var10)) {
               throw new InvalidCipherTextException("mac check in CCM failed");
            }
         }

         return var6;
      }
   }

   private int calculateMac(byte[] var1, int var2, int var3, byte[] var4) {
      CBCBlockCipherMac var5 = new CBCBlockCipherMac(this.cipher, this.macSize * 8);
      var5.init(this.keyParam);
      byte[] var6 = new byte[16];
      if (this.hasAssociatedText()) {
         var6[0] = (byte)(var6[0] | 64);
      }

      var6[0] = (byte)(var6[0] | ((var5.getMacSize() - 2) / 2 & 7) << 3);
      var6[0] = (byte)(var6[0] | 15 - this.nonce.length - 1 & 7);
      System.arraycopy(this.nonce, 0, var6, 1, this.nonce.length);
      int var7 = var3;

      for(int var8 = 1; var7 > 0; ++var8) {
         var6[var6.length - var8] = (byte)(var7 & 255);
         var7 >>>= 8;
      }

      var5.update(var6, 0, var6.length);
      if (this.hasAssociatedText()) {
         int var10 = this.getAssociatedTextLength();
         byte var9;
         if (var10 < 65280) {
            var5.update((byte)(var10 >> 8));
            var5.update((byte)var10);
            var9 = 2;
         } else {
            var5.update((byte)-1);
            var5.update((byte)-2);
            var5.update((byte)(var10 >> 24));
            var5.update((byte)(var10 >> 16));
            var5.update((byte)(var10 >> 8));
            var5.update((byte)var10);
            var9 = 6;
         }

         if (this.initialAssociatedText != null) {
            var5.update(this.initialAssociatedText, 0, this.initialAssociatedText.length);
         }

         if (this.associatedText.size() > 0) {
            byte[] var11 = this.associatedText.toByteArray();
            var5.update(var11, 0, var11.length);
         }

         int var12 = (var9 + var10) % 16;
         if (var12 != 0) {
            for(int var13 = 0; var13 != 16 - var12; ++var13) {
               var5.update((byte)0);
            }
         }
      }

      var5.update(var1, var2, var3);
      return var5.doFinal(var4, 0);
   }

   private int getAssociatedTextLength() {
      return this.associatedText.size() + (this.initialAssociatedText == null ? 0 : this.initialAssociatedText.length);
   }

   private boolean hasAssociatedText() {
      return this.getAssociatedTextLength() > 0;
   }
}
