package org.bc.crypto.signers;

import java.security.SecureRandom;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.CryptoException;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.Digest;
import org.bc.crypto.Signer;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.params.RSABlindingParameters;
import org.bc.crypto.params.RSAKeyParameters;

public class PSSSigner implements Signer {
   public static final byte TRAILER_IMPLICIT = -68;
   private Digest contentDigest;
   private Digest mgfDigest;
   private AsymmetricBlockCipher cipher;
   private SecureRandom random;
   private int hLen;
   private int mgfhLen;
   private int sLen;
   private int emBits;
   private byte[] salt;
   private byte[] mDash;
   private byte[] block;
   private byte trailer;

   public PSSSigner(AsymmetricBlockCipher var1, Digest var2, int var3) {
      this(var1, var2, var3, (byte)-68);
   }

   public PSSSigner(AsymmetricBlockCipher var1, Digest var2, Digest var3, int var4) {
      this(var1, var2, var3, var4, (byte)-68);
   }

   public PSSSigner(AsymmetricBlockCipher var1, Digest var2, int var3, byte var4) {
      this(var1, var2, var2, var3, var4);
   }

   public PSSSigner(AsymmetricBlockCipher var1, Digest var2, Digest var3, int var4, byte var5) {
      this.cipher = var1;
      this.contentDigest = var2;
      this.mgfDigest = var3;
      this.hLen = var2.getDigestSize();
      this.mgfhLen = var3.getDigestSize();
      this.sLen = var4;
      this.salt = new byte[var4];
      this.mDash = new byte[8 + var4 + this.hLen];
      this.trailer = var5;
   }

   public void init(boolean var1, CipherParameters var2) {
      CipherParameters var3;
      if (var2 instanceof ParametersWithRandom) {
         ParametersWithRandom var4 = (ParametersWithRandom)var2;
         var3 = var4.getParameters();
         this.random = var4.getRandom();
      } else {
         var3 = var2;
         if (var1) {
            this.random = new SecureRandom();
         }
      }

      this.cipher.init(var1, var3);
      RSAKeyParameters var5;
      if (var3 instanceof RSABlindingParameters) {
         var5 = ((RSABlindingParameters)var3).getPublicKey();
      } else {
         var5 = (RSAKeyParameters)var3;
      }

      this.emBits = var5.getModulus().bitLength() - 1;
      if (this.emBits < 8 * this.hLen + 8 * this.sLen + 9) {
         throw new IllegalArgumentException("key too small for specified hash and salt lengths");
      } else {
         this.block = new byte[(this.emBits + 7) / 8];
         this.reset();
      }
   }

   private void clearBlock(byte[] var1) {
      for(int var2 = 0; var2 != var1.length; ++var2) {
         var1[var2] = 0;
      }

   }

   public void update(byte var1) {
      this.contentDigest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.contentDigest.update(var1, var2, var3);
   }

   public void reset() {
      this.contentDigest.reset();
   }

   public byte[] generateSignature() throws CryptoException, DataLengthException {
      this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen - this.sLen);
      if (this.sLen != 0) {
         this.random.nextBytes(this.salt);
         System.arraycopy(this.salt, 0, this.mDash, this.mDash.length - this.sLen, this.sLen);
      }

      byte[] var1 = new byte[this.hLen];
      this.contentDigest.update(this.mDash, 0, this.mDash.length);
      this.contentDigest.doFinal(var1, 0);
      this.block[this.block.length - this.sLen - 1 - this.hLen - 1] = 1;
      System.arraycopy(this.salt, 0, this.block, this.block.length - this.sLen - this.hLen - 1, this.sLen);
      byte[] var2 = this.maskGeneratorFunction1(var1, 0, var1.length, this.block.length - this.hLen - 1);

      for(int var3 = 0; var3 != var2.length; ++var3) {
         this.block[var3] ^= var2[var3];
      }

      this.block[0] = (byte)(this.block[0] & 255 >> this.block.length * 8 - this.emBits);
      System.arraycopy(var1, 0, this.block, this.block.length - this.hLen - 1, this.hLen);
      this.block[this.block.length - 1] = this.trailer;
      byte[] var4 = this.cipher.processBlock(this.block, 0, this.block.length);
      this.clearBlock(this.block);
      return var4;
   }

   public boolean verifySignature(byte[] var1) {
      this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen - this.sLen);

      byte[] var2;
      try {
         var2 = this.cipher.processBlock(var1, 0, var1.length);
         System.arraycopy(var2, 0, this.block, this.block.length - var2.length, var2.length);
      } catch (Exception var5) {
         return false;
      }

      if (this.block[this.block.length - 1] != this.trailer) {
         this.clearBlock(this.block);
         return false;
      } else {
         var2 = this.maskGeneratorFunction1(this.block, this.block.length - this.hLen - 1, this.hLen, this.block.length - this.hLen - 1);

         int var3;
         for(var3 = 0; var3 != var2.length; ++var3) {
            this.block[var3] ^= var2[var3];
         }

         this.block[0] = (byte)(this.block[0] & 255 >> this.block.length * 8 - this.emBits);

         for(var3 = 0; var3 != this.block.length - this.hLen - this.sLen - 2; ++var3) {
            if (this.block[var3] != 0) {
               this.clearBlock(this.block);
               return false;
            }
         }

         if (this.block[this.block.length - this.hLen - this.sLen - 2] != 1) {
            this.clearBlock(this.block);
            return false;
         } else {
            System.arraycopy(this.block, this.block.length - this.sLen - this.hLen - 1, this.mDash, this.mDash.length - this.sLen, this.sLen);
            this.contentDigest.update(this.mDash, 0, this.mDash.length);
            this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen);
            var3 = this.block.length - this.hLen - 1;

            for(int var4 = this.mDash.length - this.hLen; var4 != this.mDash.length; ++var4) {
               if ((this.block[var3] ^ this.mDash[var4]) != 0) {
                  this.clearBlock(this.mDash);
                  this.clearBlock(this.block);
                  return false;
               }

               ++var3;
            }

            this.clearBlock(this.mDash);
            this.clearBlock(this.block);
            return true;
         }
      }
   }

   private void ItoOSP(int var1, byte[] var2) {
      var2[0] = (byte)(var1 >>> 24);
      var2[1] = (byte)(var1 >>> 16);
      var2[2] = (byte)(var1 >>> 8);
      var2[3] = (byte)(var1 >>> 0);
   }

   private byte[] maskGeneratorFunction1(byte[] var1, int var2, int var3, int var4) {
      byte[] var5 = new byte[var4];
      byte[] var6 = new byte[this.mgfhLen];
      byte[] var7 = new byte[4];
      int var8 = 0;
      this.mgfDigest.reset();

      while(var8 < var4 / this.mgfhLen) {
         this.ItoOSP(var8, var7);
         this.mgfDigest.update(var1, var2, var3);
         this.mgfDigest.update(var7, 0, var7.length);
         this.mgfDigest.doFinal(var6, 0);
         System.arraycopy(var6, 0, var5, var8 * this.mgfhLen, this.mgfhLen);
         ++var8;
      }

      if (var8 * this.mgfhLen < var4) {
         this.ItoOSP(var8, var7);
         this.mgfDigest.update(var1, var2, var3);
         this.mgfDigest.update(var7, 0, var7.length);
         this.mgfDigest.doFinal(var6, 0);
         System.arraycopy(var6, 0, var5, var8 * this.mgfhLen, var5.length - var8 * this.mgfhLen);
      }

      return var5;
   }
}
