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
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECPoint;

public class ECGOST3410Signer implements DSA {
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
      byte[] var2 = new byte[var1.length];

      for(int var3 = 0; var3 != var2.length; ++var3) {
         var2[var3] = var1[var2.length - 1 - var3];
      }

      BigInteger var10 = new BigInteger(1, var2);
      BigInteger var4 = this.key.getParameters().getN();
      BigInteger var5 = null;
      BigInteger var6 = null;

      while(true) {
         BigInteger var7 = null;

         while(true) {
            var7 = new BigInteger(var4.bitLength(), this.random);
            if (!var7.equals(ECConstants.ZERO)) {
               ECPoint var8 = this.key.getParameters().getG().multiply(var7);
               BigInteger var9 = var8.getX().toBigInteger();
               var5 = var9.mod(var4);
               if (!var5.equals(ECConstants.ZERO)) {
                  BigInteger var12 = ((ECPrivateKeyParameters)this.key).getD();
                  var6 = var7.multiply(var10).add(var12.multiply(var5)).mod(var4);
                  if (!var6.equals(ECConstants.ZERO)) {
                     BigInteger[] var11 = new BigInteger[]{var5, var6};
                     return var11;
                  }
                  break;
               }
            }
         }
      }
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      byte[] var4 = new byte[var1.length];

      for(int var5 = 0; var5 != var4.length; ++var5) {
         var4[var5] = var1[var4.length - 1 - var5];
      }

      BigInteger var14 = new BigInteger(1, var4);
      BigInteger var6 = this.key.getParameters().getN();
      if (var2.compareTo(ECConstants.ONE) >= 0 && var2.compareTo(var6) < 0) {
         if (var3.compareTo(ECConstants.ONE) >= 0 && var3.compareTo(var6) < 0) {
            BigInteger var7 = var14.modInverse(var6);
            BigInteger var8 = var3.multiply(var7).mod(var6);
            BigInteger var9 = var6.subtract(var2).multiply(var7).mod(var6);
            ECPoint var10 = this.key.getParameters().getG();
            ECPoint var11 = ((ECPublicKeyParameters)this.key).getQ();
            ECPoint var12 = ECAlgorithms.sumOfTwoMultiplies(var10, var8, var11, var9);
            BigInteger var13 = var12.getX().toBigInteger().mod(var6);
            return var13.equals(var2);
         } else {
            return false;
         }
      } else {
         return false;
      }
   }
}
