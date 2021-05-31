package org.bc.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.engines.MyBigInteger;
import org.bc.crypto.params.ECKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.math.ec.ECAlgorithms;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECPoint;

public class ECDSASigner implements ECConstants, DSA {
   ECKeyParameters key;
   SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.random = var3.getRandom();
            this.key = (ECPrivateKeyParameters)var3.getParameters();
         } else {
            this.random = new SecureRandom();
            this.key = (ECPrivateKeyParameters)var2;
         }
      } else {
         this.key = (ECPublicKeyParameters)var2;
      }

   }

   public BigInteger[] generateSignature(byte[] var1) {
      BigInteger var2 = this.key.getParameters().getN();
      BigInteger var3 = this.calculateE(var2, var1);
      BigInteger var4 = null;
      BigInteger var5 = null;

      do {
         BigInteger var6 = null;
         int var7 = var2.bitLength();

         do {
            var6 = MyBigInteger.gen(var2, this.random);
            ECPoint var8 = this.key.getParameters().getG().multiply(var6);
            BigInteger var9 = var8.getX().toBigInteger();
            var4 = var9.mod(var2);
         } while(var4.equals(ZERO));

         BigInteger var11 = ((ECPrivateKeyParameters)this.key).getD();
         var5 = var6.modInverse(var2).multiply(var3.add(var11.multiply(var4))).mod(var2);
      } while(var5.equals(ZERO));

      BigInteger[] var10 = new BigInteger[]{var4, var5};
      return var10;
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      BigInteger var4 = this.key.getParameters().getN();
      BigInteger var5 = this.calculateE(var4, var1);
      if (var2.compareTo(ONE) >= 0 && var2.compareTo(var4) < 0) {
         if (var3.compareTo(ONE) >= 0 && var3.compareTo(var4) < 0) {
            BigInteger var6 = var3.modInverse(var4);
            BigInteger var7 = var5.multiply(var6).mod(var4);
            BigInteger var8 = var2.multiply(var6).mod(var4);
            ECPoint var9 = this.key.getParameters().getG();
            ECPoint var10 = ((ECPublicKeyParameters)this.key).getQ();
            ECPoint var11 = ECAlgorithms.sumOfTwoMultiplies(var9, var7, var10, var8);
            BigInteger var12 = var11.getX().toBigInteger().mod(var4);
            return var12.equals(var2);
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   private BigInteger calculateE(BigInteger var1, byte[] var2) {
      int var3 = var1.bitLength();
      int var4 = var2.length * 8;
      if (var3 >= var4) {
         return new BigInteger(1, var2);
      } else {
         BigInteger var5 = new BigInteger(1, var2);
         var5 = var5.shiftRight(var4 - var3);
         return var5;
      }
   }
}
