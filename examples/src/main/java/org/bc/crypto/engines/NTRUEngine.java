package org.bc.crypto.engines;

import java.security.SecureRandom;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.Digest;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.params.NTRUEncryptionParameters;
import org.bc.crypto.params.NTRUEncryptionPrivateKeyParameters;
import org.bc.crypto.params.NTRUEncryptionPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bc.math.ntru.polynomial.IntegerPolynomial;
import org.bc.math.ntru.polynomial.Polynomial;
import org.bc.math.ntru.polynomial.ProductFormPolynomial;
import org.bc.math.ntru.polynomial.SparseTernaryPolynomial;
import org.bc.math.ntru.polynomial.TernaryPolynomial;
import org.bc.util.Arrays;

public class NTRUEngine implements AsymmetricBlockCipher {
   private boolean forEncryption;
   private NTRUEncryptionParameters params;
   private NTRUEncryptionPublicKeyParameters pubKey;
   private NTRUEncryptionPrivateKeyParameters privKey;
   private SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      this.forEncryption = var1;
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.random = var3.getRandom();
            this.pubKey = (NTRUEncryptionPublicKeyParameters)var3.getParameters();
         } else {
            this.random = new SecureRandom();
            this.pubKey = (NTRUEncryptionPublicKeyParameters)var2;
         }

         this.params = this.pubKey.getParameters();
      } else {
         this.privKey = (NTRUEncryptionPrivateKeyParameters)var2;
         this.params = this.privKey.getParameters();
      }

   }

   public int getInputBlockSize() {
      return this.params.maxMsgLenBytes;
   }

   public int getOutputBlockSize() {
      return (this.params.N * this.log2(this.params.q) + 7) / 8;
   }

   public byte[] processBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
      byte[] var4 = new byte[var3];
      System.arraycopy(var1, var2, var4, 0, var3);
      return this.forEncryption ? this.encrypt(var4, this.pubKey) : this.decrypt(var4, this.privKey);
   }

   private byte[] encrypt(byte[] var1, NTRUEncryptionPublicKeyParameters var2) {
      IntegerPolynomial var3 = var2.h;
      int var4 = this.params.N;
      int var5 = this.params.q;
      int var6 = this.params.maxMsgLenBytes;
      int var7 = this.params.db;
      int var8 = this.params.bufferLenBits;
      int var9 = this.params.dm0;
      int var10 = this.params.pkLen;
      int var11 = this.params.minCallsMask;
      boolean var12 = this.params.hashSeed;
      byte[] var13 = this.params.oid;
      int var14 = var1.length;
      if (var6 > 255) {
         throw new IllegalArgumentException("llen values bigger than 1 are not supported");
      } else if (var14 > var6) {
         throw new DataLengthException("Message too long: " + var14 + ">" + var6);
      } else {
         IntegerPolynomial var18;
         IntegerPolynomial var23;
         do {
            while(true) {
               byte[] var15 = new byte[var7 / 8];
               this.random.nextBytes(var15);
               byte[] var16 = new byte[var6 + 1 - var14];
               byte[] var17 = new byte[var8 / 8];
               System.arraycopy(var15, 0, var17, 0, var15.length);
               var17[var15.length] = (byte)var14;
               System.arraycopy(var1, 0, var17, var15.length + 1, var1.length);
               System.arraycopy(var16, 0, var17, var15.length + 1 + var1.length, var16.length);
               var18 = IntegerPolynomial.fromBinary3Sves(var17, var4);
               byte[] var19 = var3.toBinary(var5);
               byte[] var20 = this.copyOf(var19, var10 / 8);
               byte[] var21 = this.buildSData(var13, var1, var14, var15, var20);
               Polynomial var22 = this.generateBlindingPoly(var21, var17);
               var23 = var22.mult(var3, var5);
               IntegerPolynomial var24 = (IntegerPolynomial)var23.clone();
               var24.modPositive(4);
               byte[] var25 = var24.toBinary(4);
               IntegerPolynomial var26 = this.MGF(var25, var4, var11, var12);
               var18.add(var26);
               var18.mod3();
               if (var18.count(-1) < var9) {
                  continue;
               }
               break;
            }
         } while(var18.count(0) < var9 || var18.count(1) < var9);

         var23.add(var18, var5);
         var23.ensurePositive(var5);
         return var23.toBinary(var5);
      }
   }

   private byte[] buildSData(byte[] var1, byte[] var2, int var3, byte[] var4, byte[] var5) {
      byte[] var6 = new byte[var1.length + var3 + var4.length + var5.length];
      System.arraycopy(var1, 0, var6, 0, var1.length);
      System.arraycopy(var2, 0, var6, var1.length, var2.length);
      System.arraycopy(var4, 0, var6, var1.length + var2.length, var4.length);
      System.arraycopy(var5, 0, var6, var1.length + var2.length + var4.length, var5.length);
      return var6;
   }

   protected IntegerPolynomial encrypt(IntegerPolynomial var1, TernaryPolynomial var2, IntegerPolynomial var3) {
      IntegerPolynomial var4 = var2.mult(var3, this.params.q);
      var4.add(var1, this.params.q);
      var4.ensurePositive(this.params.q);
      return var4;
   }

   private Polynomial generateBlindingPoly(byte[] var1, byte[] var2) {
      IndexGenerator var3 = new IndexGenerator(var1, this.params);
      if (this.params.polyType == 1) {
         SparseTernaryPolynomial var9 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(var3, this.params.dr1));
         SparseTernaryPolynomial var7 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(var3, this.params.dr2));
         SparseTernaryPolynomial var8 = new SparseTernaryPolynomial(this.generateBlindingCoeffs(var3, this.params.dr3));
         return new ProductFormPolynomial(var9, var7, var8);
      } else {
         int var4 = this.params.dr;
         boolean var5 = this.params.sparse;
         int[] var6 = this.generateBlindingCoeffs(var3, var4);
         return (Polynomial)(var5 ? new SparseTernaryPolynomial(var6) : new DenseTernaryPolynomial(var6));
      }
   }

   private int[] generateBlindingCoeffs(IndexGenerator var1, int var2) {
      int var3 = this.params.N;
      int[] var4 = new int[var3];

      for(int var5 = -1; var5 <= 1; var5 += 2) {
         int var6 = 0;

         while(var6 < var2) {
            int var7 = var1.nextIndex();
            if (var4[var7] == 0) {
               var4[var7] = var5;
               ++var6;
            }
         }
      }

      return var4;
   }

   private IntegerPolynomial MGF(byte[] var1, int var2, int var3, boolean var4) {
      Digest var5 = this.params.hashAlg;
      int var6 = var5.getDigestSize();
      byte[] var7 = new byte[var3 * var6];
      byte[] var8 = var4 ? this.calcHash(var5, var1) : var1;

      int var9;
      for(var9 = 0; var9 < var3; ++var9) {
         var5.update(var8, 0, var8.length);
         this.putInt(var5, var9);
         byte[] var10 = this.calcHash(var5);
         System.arraycopy(var10, 0, var7, var9 * var6, var6);
      }

      IntegerPolynomial var16 = new IntegerPolynomial(var2);

      while(true) {
         int var11 = 0;

         for(int var12 = 0; var12 != var7.length; ++var12) {
            int var13 = var7[var12] & 255;
            if (var13 < 243) {
               for(int var14 = 0; var14 < 4; ++var14) {
                  int var15 = var13 % 3;
                  var16.coeffs[var11] = var15 - 1;
                  ++var11;
                  if (var11 == var2) {
                     return var16;
                  }

                  var13 = (var13 - var15) / 3;
               }

               var16.coeffs[var11] = var13 - 1;
               ++var11;
               if (var11 == var2) {
                  return var16;
               }
            }
         }

         if (var11 >= var2) {
            return var16;
         }

         var5.update(var8, 0, var8.length);
         this.putInt(var5, var9);
         byte[] var17 = this.calcHash(var5);
         var7 = var17;
         ++var9;
      }
   }

   private void putInt(Digest var1, int var2) {
      var1.update((byte)(var2 >> 24));
      var1.update((byte)(var2 >> 16));
      var1.update((byte)(var2 >> 8));
      var1.update((byte)var2);
   }

   private byte[] calcHash(Digest var1) {
      byte[] var2 = new byte[var1.getDigestSize()];
      var1.doFinal(var2, 0);
      return var2;
   }

   private byte[] calcHash(Digest var1, byte[] var2) {
      byte[] var3 = new byte[var1.getDigestSize()];
      var1.update(var2, 0, var2.length);
      var1.doFinal(var3, 0);
      return var3;
   }

   private byte[] decrypt(byte[] var1, NTRUEncryptionPrivateKeyParameters var2) throws InvalidCipherTextException {
      Polynomial var3 = var2.t;
      IntegerPolynomial var4 = var2.fp;
      IntegerPolynomial var5 = var2.h;
      int var6 = this.params.N;
      int var7 = this.params.q;
      int var8 = this.params.db;
      int var9 = this.params.maxMsgLenBytes;
      int var10 = this.params.dm0;
      int var11 = this.params.pkLen;
      int var12 = this.params.minCallsMask;
      boolean var13 = this.params.hashSeed;
      byte[] var14 = this.params.oid;
      if (var9 > 255) {
         throw new DataLengthException("maxMsgLenBytes values bigger than 255 are not supported");
      } else {
         int var15 = var8 / 8;
         IntegerPolynomial var16 = IntegerPolynomial.fromBinary(var1, var6, var7);
         IntegerPolynomial var17 = this.decrypt(var16, var3, var4);
         if (var17.count(-1) < var10) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal -1");
         } else if (var17.count(0) < var10) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal 0");
         } else if (var17.count(1) < var10) {
            throw new InvalidCipherTextException("Less than dm0 coefficients equal 1");
         } else {
            IntegerPolynomial var18 = (IntegerPolynomial)var16.clone();
            var18.sub(var17);
            var18.modPositive(var7);
            IntegerPolynomial var19 = (IntegerPolynomial)var18.clone();
            var19.modPositive(4);
            byte[] var20 = var19.toBinary(4);
            IntegerPolynomial var21 = this.MGF(var20, var6, var12, var13);
            var17.sub(var21);
            var17.mod3();
            byte[] var23 = var17.toBinary3Sves();
            byte[] var24 = new byte[var15];
            System.arraycopy(var23, 0, var24, 0, var15);
            int var25 = var23[var15] & 255;
            if (var25 > var9) {
               throw new InvalidCipherTextException("Message too long: " + var25 + ">" + var9);
            } else {
               byte[] var26 = new byte[var25];
               System.arraycopy(var23, var15 + 1, var26, 0, var25);
               byte[] var27 = new byte[var23.length - (var15 + 1 + var25)];
               System.arraycopy(var23, var15 + 1 + var25, var27, 0, var27.length);
               if (!Arrays.areEqual(var27, new byte[var27.length])) {
                  throw new InvalidCipherTextException("The message is not followed by zeroes");
               } else {
                  byte[] var28 = var5.toBinary(var7);
                  byte[] var29 = this.copyOf(var28, var11 / 8);
                  byte[] var30 = this.buildSData(var14, var26, var25, var24, var29);
                  Polynomial var31 = this.generateBlindingPoly(var30, var26);
                  IntegerPolynomial var32 = var31.mult(var5);
                  var32.modPositive(var7);
                  if (!var32.equals(var18)) {
                     throw new InvalidCipherTextException("Invalid message encoding");
                  } else {
                     return var26;
                  }
               }
            }
         }
      }
   }

   protected IntegerPolynomial decrypt(IntegerPolynomial var1, Polynomial var2, IntegerPolynomial var3) {
      IntegerPolynomial var4;
      if (this.params.fastFp) {
         var4 = var2.mult(var1, this.params.q);
         var4.mult(3);
         var4.add(var1);
      } else {
         var4 = var2.mult(var1, this.params.q);
      }

      var4.center0(this.params.q);
      var4.mod3();
      IntegerPolynomial var5 = this.params.fastFp ? var4 : (new DenseTernaryPolynomial(var4)).mult(var3, 3);
      var5.center0(3);
      return var5;
   }

   private byte[] copyOf(byte[] var1, int var2) {
      byte[] var3 = new byte[var2];
      System.arraycopy(var1, 0, var3, 0, var2 < var1.length ? var2 : var1.length);
      return var3;
   }

   private int log2(int var1) {
      if (var1 == 2048) {
         return 11;
      } else {
         throw new IllegalStateException("log2 not fully implemented");
      }
   }
}
