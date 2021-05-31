package org.bc.crypto.encodings;

import java.security.SecureRandom;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.params.ParametersWithRandom;

public class OAEPEncoding implements AsymmetricBlockCipher {
   private byte[] defHash;
   private Digest hash;
   private Digest mgf1Hash;
   private AsymmetricBlockCipher engine;
   private SecureRandom random;
   private boolean forEncryption;

   public OAEPEncoding(AsymmetricBlockCipher var1) {
      this(var1, new SHA1Digest(), (byte[])null);
   }

   public OAEPEncoding(AsymmetricBlockCipher var1, Digest var2) {
      this(var1, var2, (byte[])null);
   }

   public OAEPEncoding(AsymmetricBlockCipher var1, Digest var2, byte[] var3) {
      this(var1, var2, var2, var3);
   }

   public OAEPEncoding(AsymmetricBlockCipher var1, Digest var2, Digest var3, byte[] var4) {
      this.engine = var1;
      this.hash = var2;
      this.mgf1Hash = var3;
      this.defHash = new byte[var2.getDigestSize()];
      if (var4 != null) {
         var2.update(var4, 0, var4.length);
      }

      var2.doFinal(this.defHash, 0);
   }

   public AsymmetricBlockCipher getUnderlyingCipher() {
      return this.engine;
   }

   public void init(boolean var1, CipherParameters var2) {
      if (var2 instanceof ParametersWithRandom) {
         ParametersWithRandom var3 = (ParametersWithRandom)var2;
         this.random = var3.getRandom();
      } else {
         this.random = new SecureRandom();
      }

      this.engine.init(var1, var2);
      this.forEncryption = var1;
   }

   public int getInputBlockSize() {
      int var1 = this.engine.getInputBlockSize();
      return this.forEncryption ? var1 - 1 - 2 * this.defHash.length : var1;
   }

   public int getOutputBlockSize() {
      int var1 = this.engine.getOutputBlockSize();
      return this.forEncryption ? var1 : var1 - 1 - 2 * this.defHash.length;
   }

   public byte[] processBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      return this.forEncryption ? this.encodeBlock(var1, var2, var3) : this.decodeBlock(var1, var2, var3);
   }

   public byte[] encodeBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      byte[] var4 = new byte[this.getInputBlockSize() + 1 + 2 * this.defHash.length];
      System.arraycopy(var1, var2, var4, var4.length - var3, var3);
      var4[var4.length - var3 - 1] = 1;
      System.arraycopy(this.defHash, 0, var4, this.defHash.length, this.defHash.length);
      byte[] var5 = new byte[this.defHash.length];
      this.random.nextBytes(var5);
      byte[] var6 = this.maskGeneratorFunction1(var5, 0, var5.length, var4.length - this.defHash.length);

      int var7;
      for(var7 = this.defHash.length; var7 != var4.length; ++var7) {
         var4[var7] ^= var6[var7 - this.defHash.length];
      }

      System.arraycopy(var5, 0, var4, 0, this.defHash.length);
      var6 = this.maskGeneratorFunction1(var4, this.defHash.length, var4.length - this.defHash.length, this.defHash.length);

      for(var7 = 0; var7 != this.defHash.length; ++var7) {
         var4[var7] ^= var6[var7];
      }

      return this.engine.processBlock(var4, 0, var4.length);
   }

   public byte[] decodeBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      byte[] var4 = this.engine.processBlock(var1, var2, var3);
      byte[] var5;
      if (var4.length < this.engine.getOutputBlockSize()) {
         var5 = new byte[this.engine.getOutputBlockSize()];
         System.arraycopy(var4, 0, var5, var5.length - var4.length, var4.length);
      } else {
         var5 = var4;
      }

      if (var5.length < 2 * this.defHash.length + 1) {
         throw new InvalidCipherTextException("data too short");
      } else {
         byte[] var6 = this.maskGeneratorFunction1(var5, this.defHash.length, var5.length - this.defHash.length, this.defHash.length);

         int var7;
         for(var7 = 0; var7 != this.defHash.length; ++var7) {
            var5[var7] ^= var6[var7];
         }

         var6 = this.maskGeneratorFunction1(var5, 0, this.defHash.length, var5.length - this.defHash.length);

         for(var7 = this.defHash.length; var7 != var5.length; ++var7) {
            var5[var7] ^= var6[var7 - this.defHash.length];
         }

         for(var7 = 0; var7 != this.defHash.length; ++var7) {
            if (this.defHash[var7] != var5[this.defHash.length + var7]) {
               throw new InvalidCipherTextException("data hash wrong");
            }
         }

         for(var7 = 2 * this.defHash.length; var7 != var5.length && var5[var7] == 0; ++var7) {
            ;
         }

         if (var7 < var5.length - 1 && var5[var7] == 1) {
            ++var7;
            byte[] var8 = new byte[var5.length - var7];
            System.arraycopy(var5, var7, var8, 0, var8.length);
            return var8;
         } else {
            throw new InvalidCipherTextException("data start wrong " + var7);
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
      byte[] var6 = new byte[this.mgf1Hash.getDigestSize()];
      byte[] var7 = new byte[4];
      int var8 = 0;
      this.hash.reset();

      do {
         this.ItoOSP(var8, var7);
         this.mgf1Hash.update(var1, var2, var3);
         this.mgf1Hash.update(var7, 0, var7.length);
         this.mgf1Hash.doFinal(var6, 0);
         System.arraycopy(var6, 0, var5, var8 * var6.length, var6.length);
         ++var8;
      } while(var8 < var4 / var6.length);

      if (var8 * var6.length < var4) {
         this.ItoOSP(var8, var7);
         this.mgf1Hash.update(var1, var2, var3);
         this.mgf1Hash.update(var7, 0, var7.length);
         this.mgf1Hash.doFinal(var6, 0);
         System.arraycopy(var6, 0, var5, var8 * var6.length, var5.length - var8 * var6.length);
      }

      return var5;
   }
}
