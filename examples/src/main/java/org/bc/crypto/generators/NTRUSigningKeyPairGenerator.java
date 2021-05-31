package org.bc.crypto.generators;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.NTRUSigningKeyGenerationParameters;
import org.bc.crypto.params.NTRUSigningPrivateKeyParameters;
import org.bc.crypto.params.NTRUSigningPublicKeyParameters;
import org.bc.math.ntru.euclid.BigIntEuclidean;
import org.bc.math.ntru.polynomial.BigDecimalPolynomial;
import org.bc.math.ntru.polynomial.BigIntPolynomial;
import org.bc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bc.math.ntru.polynomial.IntegerPolynomial;
import org.bc.math.ntru.polynomial.Polynomial;
import org.bc.math.ntru.polynomial.ProductFormPolynomial;
import org.bc.math.ntru.polynomial.Resultant;

public class NTRUSigningKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private NTRUSigningKeyGenerationParameters params;

   public void init(KeyGenerationParameters var1) {
      this.params = (NTRUSigningKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      NTRUSigningPublicKeyParameters var1 = null;
      ExecutorService var2 = Executors.newCachedThreadPool();
      ArrayList var3 = new ArrayList();

      for(int var4 = this.params.B; var4 >= 0; --var4) {
         var3.add(var2.submit(new NTRUSigningKeyPairGenerator.BasisGenerationTask((NTRUSigningKeyPairGenerator.BasisGenerationTask)null)));
      }

      var2.shutdown();
      ArrayList var9 = new ArrayList();

      for(int var5 = this.params.B; var5 >= 0; --var5) {
         Future var6 = (Future)var3.get(var5);

         try {
            var9.add((NTRUSigningPrivateKeyParameters.Basis)var6.get());
            if (var5 == this.params.B) {
               var1 = new NTRUSigningPublicKeyParameters(((NTRUSigningPrivateKeyParameters.Basis)var6.get()).h, this.params.getSigningParameters());
            }
         } catch (Exception var8) {
            throw new IllegalStateException(var8);
         }
      }

      NTRUSigningPrivateKeyParameters var10 = new NTRUSigningPrivateKeyParameters(var9, var1);
      AsymmetricCipherKeyPair var11 = new AsymmetricCipherKeyPair(var1, var10);
      return var11;
   }

   public AsymmetricCipherKeyPair generateKeyPairSingleThread() {
      ArrayList var1 = new ArrayList();
      NTRUSigningPublicKeyParameters var2 = null;

      for(int var3 = this.params.B; var3 >= 0; --var3) {
         NTRUSigningPrivateKeyParameters.Basis var4 = this.generateBoundedBasis();
         var1.add(var4);
         if (var3 == 0) {
            var2 = new NTRUSigningPublicKeyParameters(var4.h, this.params.getSigningParameters());
         }
      }

      NTRUSigningPrivateKeyParameters var5 = new NTRUSigningPrivateKeyParameters(var1, var2);
      return new AsymmetricCipherKeyPair(var2, var5);
   }

   private void minimizeFG(IntegerPolynomial var1, IntegerPolynomial var2, IntegerPolynomial var3, IntegerPolynomial var4, int var5) {
      int var6 = 0;

      for(int var7 = 0; var7 < var5; ++var7) {
         var6 += 2 * var5 * (var1.coeffs[var7] * var1.coeffs[var7] + var2.coeffs[var7] * var2.coeffs[var7]);
      }

      var6 -= 4;
      IntegerPolynomial var17 = (IntegerPolynomial)var1.clone();
      IntegerPolynomial var8 = (IntegerPolynomial)var2.clone();
      int var9 = 0;
      int var10 = 0;
      int var11 = var5;

      while(var10 < var11 && var9 < var5) {
         int var12 = 0;

         int var14;
         for(int var13 = 0; var13 < var5; ++var13) {
            var14 = var3.coeffs[var13] * var1.coeffs[var13];
            int var15 = var4.coeffs[var13] * var2.coeffs[var13];
            int var16 = 4 * var5 * (var14 + var15);
            var12 += var16;
         }

         var14 = 4 * (var3.sumCoeffs() + var4.sumCoeffs());
         var12 -= var14;
         if (var12 > var6) {
            var3.sub(var17);
            var4.sub(var8);
            ++var10;
            var9 = 0;
         } else if (var12 < -var6) {
            var3.add(var17);
            var4.add(var8);
            ++var10;
            var9 = 0;
         }

         ++var9;
         var17.rotate1();
         var8.rotate1();
      }

   }

   private NTRUSigningKeyPairGenerator.FGBasis generateBasis() {
      int var1 = this.params.N;
      int var2 = this.params.q;
      int var3 = this.params.d;
      int var4 = this.params.d1;
      int var5 = this.params.d2;
      int var6 = this.params.d3;
      int var7 = this.params.basisType;
      int var16 = 2 * var1 + 1;
      boolean var17 = this.params.primeCheck;

      Object var8;
      IntegerPolynomial var9;
      IntegerPolynomial var12;
      do {
         do {
            var8 = this.params.polyType == 0 ? DenseTernaryPolynomial.generateRandom(var1, var3 + 1, var3, new SecureRandom()) : ProductFormPolynomial.generateRandom(var1, var4, var5, var6 + 1, var6, new SecureRandom());
            var9 = ((Polynomial)var8).toIntegerPolynomial();
         } while(var17 && var9.resultant(var16).res.equals(BigInteger.ZERO));

         var12 = var9.invertFq(var2);
      } while(var12 == null);

      Resultant var13 = var9.resultant();

      while(true) {
         Object var10;
         IntegerPolynomial var11;
         do {
            var10 = this.params.polyType == 0 ? DenseTernaryPolynomial.generateRandom(var1, var3 + 1, var3, new SecureRandom()) : ProductFormPolynomial.generateRandom(var1, var4, var5, var6 + 1, var6, new SecureRandom());
            var11 = ((Polynomial)var10).toIntegerPolynomial();
         } while(var17 && var11.resultant(var16).res.equals(BigInteger.ZERO));

         if (var11.invertFq(var2) != null) {
            Resultant var14 = var11.resultant();
            BigIntEuclidean var15 = BigIntEuclidean.calculate(var13.res, var14.res);
            if (var15.gcd.equals(BigInteger.ONE)) {
               BigIntPolynomial var18 = (BigIntPolynomial)var13.rho.clone();
               var18.mult(var15.x.multiply(BigInteger.valueOf((long)var2)));
               BigIntPolynomial var19 = (BigIntPolynomial)var14.rho.clone();
               var19.mult(var15.y.multiply(BigInteger.valueOf((long)(-var2))));
               BigIntPolynomial var20;
               IntegerPolynomial var24;
               IntegerPolynomial var32;
               if (this.params.keyGenAlg == 0) {
                  int[] var21 = new int[var1];
                  int[] var22 = new int[var1];
                  var21[0] = var9.coeffs[0];
                  var22[0] = var11.coeffs[0];

                  for(int var23 = 1; var23 < var1; ++var23) {
                     var21[var23] = var9.coeffs[var1 - var23];
                     var22[var23] = var11.coeffs[var1 - var23];
                  }

                  var32 = new IntegerPolynomial(var21);
                  var24 = new IntegerPolynomial(var22);
                  IntegerPolynomial var25 = ((Polynomial)var8).mult(var32);
                  var25.add(((Polynomial)var10).mult(var24));
                  Resultant var26 = var25.resultant();
                  var20 = var32.mult(var19);
                  var20.add(var24.mult(var18));
                  var20 = var20.mult(var26.rho);
                  var20.div(var26.res);
               } else {
                  int var27 = 0;

                  for(int var29 = 1; var29 < var1; var29 *= 10) {
                     ++var27;
                  }

                  BigDecimalPolynomial var30 = var13.rho.div(new BigDecimal(var13.res), var19.getMaxCoeffLength() + 1 + var27);
                  BigDecimalPolynomial var33 = var14.rho.div(new BigDecimal(var14.res), var18.getMaxCoeffLength() + 1 + var27);
                  BigDecimalPolynomial var34 = var30.mult(var19);
                  var34.add(var33.mult(var18));
                  var34.halve();
                  var20 = var34.round();
               }

               BigIntPolynomial var28 = (BigIntPolynomial)var19.clone();
               var28.sub(((Polynomial)var8).mult(var20));
               BigIntPolynomial var31 = (BigIntPolynomial)var18.clone();
               var31.sub(((Polynomial)var10).mult(var20));
               var32 = new IntegerPolynomial(var28);
               var24 = new IntegerPolynomial(var31);
               this.minimizeFG(var9, var11, var32, var24, var1);
               Object var35;
               IntegerPolynomial var36;
               if (var7 == 0) {
                  var35 = var32;
                  var36 = ((Polynomial)var10).mult(var12, var2);
               } else {
                  var35 = var10;
                  var36 = var32.mult(var12, var2);
               }

               var36.modPositive(var2);
               return new NTRUSigningKeyPairGenerator.FGBasis((Polynomial)var8, (Polynomial)var35, var36, var32, var24, this.params);
            }
         }
      }
   }

   public NTRUSigningPrivateKeyParameters.Basis generateBoundedBasis() {
      NTRUSigningKeyPairGenerator.FGBasis var1;
      do {
         var1 = this.generateBasis();
      } while(!var1.isNormOk());

      return var1;
   }

   private class BasisGenerationTask implements Callable<NTRUSigningPrivateKeyParameters.Basis> {
      private BasisGenerationTask() {
      }

      public NTRUSigningPrivateKeyParameters.Basis call() throws Exception {
         return NTRUSigningKeyPairGenerator.this.generateBoundedBasis();
      }

      // $FF: synthetic method
      BasisGenerationTask(NTRUSigningKeyPairGenerator.BasisGenerationTask var2) {
         this();
      }
   }

   public class FGBasis extends NTRUSigningPrivateKeyParameters.Basis {
      public IntegerPolynomial F;
      public IntegerPolynomial G;

      FGBasis(Polynomial var2, Polynomial var3, IntegerPolynomial var4, IntegerPolynomial var5, IntegerPolynomial var6, NTRUSigningKeyGenerationParameters var7) {
         super(var2, var3, var4, var7);
         this.F = var5;
         this.G = var6;
      }

      boolean isNormOk() {
         double var1 = NTRUSigningKeyPairGenerator.this.params.keyNormBoundSq;
         int var3 = NTRUSigningKeyPairGenerator.this.params.q;
         return (double)this.F.centeredNormSq(var3) < var1 && (double)this.G.centeredNormSq(var3) < var1;
      }
   }
}
