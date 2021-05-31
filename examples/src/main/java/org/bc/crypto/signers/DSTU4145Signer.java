package org.bc.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.params.ECKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.math.ec.ECAlgorithms;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECFieldElement;
import org.bc.math.ec.ECPoint;
import org.bc.util.Arrays;

public class DSTU4145Signer implements DSA {
   private static final BigInteger ONE = BigInteger.valueOf(1L);
   private ECKeyParameters key;
   private SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.random = var3.getRandom();
            var2 = var3.getParameters();
         } else {
            this.random = new SecureRandom();
         }

         this.key = (ECPrivateKeyParameters)var2;
      } else {
         this.key = (ECPublicKeyParameters)var2;
      }

   }

   public BigInteger[] generateSignature(byte[] var1) {
      ECFieldElement var2 = hash2FieldElement(this.key.getParameters().getCurve(), var1);
      if (var2.toBigInteger().signum() == 0) {
         var2 = this.key.getParameters().getCurve().fromBigInteger(ONE);
      }

      while(true) {
         BigInteger var3;
         ECFieldElement var6;
         do {
            var3 = generateRandomInteger(this.key.getParameters().getN(), this.random);
            var6 = this.key.getParameters().getG().multiply(var3).getX();
         } while(var6.toBigInteger().signum() == 0);

         ECFieldElement var7 = var2.multiply(var6);
         BigInteger var4 = fieldElement2Integer(this.key.getParameters().getN(), var7);
         if (var4.signum() != 0) {
            BigInteger var5 = var4.multiply(((ECPrivateKeyParameters)this.key).getD()).add(var3).mod(this.key.getParameters().getN());
            if (var5.signum() != 0) {
               return new BigInteger[]{var4, var5};
            }
         }
      }
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      if (var2.signum() != 0 && var3.signum() != 0) {
         if (var2.compareTo(this.key.getParameters().getN()) < 0 && var3.compareTo(this.key.getParameters().getN()) < 0) {
            ECFieldElement var4 = hash2FieldElement(this.key.getParameters().getCurve(), var1);
            if (var4.toBigInteger().signum() == 0) {
               var4 = this.key.getParameters().getCurve().fromBigInteger(ONE);
            }

            ECPoint var5 = ECAlgorithms.sumOfTwoMultiplies(this.key.getParameters().getG(), var3, ((ECPublicKeyParameters)this.key).getQ(), var2);
            ECFieldElement var6 = var4.multiply(var5.getX());
            return fieldElement2Integer(this.key.getParameters().getN(), var6).compareTo(var2) == 0;
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   private static BigInteger generateRandomInteger(BigInteger var0, SecureRandom var1) {
      return new BigInteger(var0.bitLength() - 1, var1);
   }

   private static void reverseBytes(byte[] var0) {
      for(int var2 = 0; var2 < var0.length / 2; ++var2) {
         byte var1 = var0[var2];
         var0[var2] = var0[var0.length - 1 - var2];
         var0[var0.length - 1 - var2] = var1;
      }

   }

   private static ECFieldElement hash2FieldElement(ECCurve var0, byte[] var1) {
      byte[] var2 = Arrays.clone(var1);
      reverseBytes(var2);

      BigInteger var3;
      for(var3 = new BigInteger(1, var2); var3.bitLength() >= var0.getFieldSize(); var3 = var3.clearBit(var3.bitLength() - 1)) {
         ;
      }

      return var0.fromBigInteger(var3);
   }

   private static BigInteger fieldElement2Integer(BigInteger var0, ECFieldElement var1) {
      BigInteger var2;
      for(var2 = var1.toBigInteger(); var2.bitLength() >= var0.bitLength(); var2 = var2.clearBit(var2.bitLength() - 1)) {
         ;
      }

      return var2;
   }
}
