package org.bc.crypto.generators;

import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.crypto.params.NTRUEncryptionKeyGenerationParameters;
import org.bc.crypto.params.NTRUEncryptionPrivateKeyParameters;
import org.bc.crypto.params.NTRUEncryptionPublicKeyParameters;
import org.bc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bc.math.ntru.polynomial.IntegerPolynomial;
import org.bc.math.ntru.polynomial.Polynomial;
import org.bc.math.ntru.polynomial.ProductFormPolynomial;
import org.bc.math.ntru.util.Util;

public class NTRUEncryptionKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   private NTRUEncryptionKeyGenerationParameters params;

   public void init(KeyGenerationParameters var1) {
      this.params = (NTRUEncryptionKeyGenerationParameters)var1;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      int var1 = this.params.N;
      int var2 = this.params.q;
      int var3 = this.params.df;
      int var4 = this.params.df1;
      int var5 = this.params.df2;
      int var6 = this.params.df3;
      int var7 = this.params.dg;
      boolean var8 = this.params.fastFp;
      boolean var9 = this.params.sparse;
      IntegerPolynomial var12 = null;

      Object var10;
      IntegerPolynomial var11;
      do {
         IntegerPolynomial var13;
         do {
            if (var8) {
               var10 = this.params.polyType == 0 ? Util.generateRandomTernary(var1, var3, var3, var9, this.params.getRandom()) : ProductFormPolynomial.generateRandom(var1, var4, var5, var6, var6, this.params.getRandom());
               var13 = ((Polynomial)var10).toIntegerPolynomial();
               var13.mult(3);
               ++var13.coeffs[0];
               break;
            }

            var10 = this.params.polyType == 0 ? Util.generateRandomTernary(var1, var3, var3 - 1, var9, this.params.getRandom()) : ProductFormPolynomial.generateRandom(var1, var4, var5, var6, var6 - 1, this.params.getRandom());
            var13 = ((Polynomial)var10).toIntegerPolynomial();
            var12 = var13.invertF3();
         } while(var12 == null);

         var11 = var13.invertFq(var2);
      } while(var11 == null);

      if (var8) {
         var12 = new IntegerPolynomial(var1);
         var12.coeffs[0] = 1;
      }

      DenseTernaryPolynomial var17;
      do {
         var17 = DenseTernaryPolynomial.generateRandom(var1, var7, var7 - 1, this.params.getRandom());
      } while(var17.invertFq(var2) == null);

      IntegerPolynomial var14 = var17.mult(var11, var2);
      var14.mult3(var2);
      var14.ensurePositive(var2);
      var17.clear();
      var11.clear();
      NTRUEncryptionPrivateKeyParameters var15 = new NTRUEncryptionPrivateKeyParameters(var14, (Polynomial)var10, var12, this.params.getEncryptionParameters());
      NTRUEncryptionPublicKeyParameters var16 = new NTRUEncryptionPublicKeyParameters(var14, this.params.getEncryptionParameters());
      return new AsymmetricCipherKeyPair(var16, var15);
   }
}
