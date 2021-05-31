package org.bc.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.generators.ECKeyPairGenerator;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.math.ec.ECAlgorithms;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECPoint;

public class ECNRSigner implements DSA {
   private boolean forSigning;
   private ECKeyParameters key;
   private SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      this.forSigning = var1;
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
      if (!this.forSigning) {
         throw new IllegalStateException("not initialised for signing");
      } else {
         BigInteger var2 = ((ECPrivateKeyParameters)this.key).getParameters().getN();
         int var3 = var2.bitLength();
         BigInteger var4 = new BigInteger(1, var1);
         int var5 = var4.bitLength();
         ECPrivateKeyParameters var6 = (ECPrivateKeyParameters)this.key;
         if (var5 > var3) {
            throw new DataLengthException("input too large for ECNR key.");
         } else {
            BigInteger var7 = null;
            BigInteger var8 = null;

            AsymmetricCipherKeyPair var9;
            do {
               ECKeyPairGenerator var10 = new ECKeyPairGenerator();
               var10.init(new ECKeyGenerationParameters(var6.getParameters(), this.random));
               var9 = var10.generateKeyPair();
               ECPublicKeyParameters var11 = (ECPublicKeyParameters)var9.getPublic();
               BigInteger var12 = var11.getQ().getX().toBigInteger();
               var7 = var12.add(var4).mod(var2);
            } while(var7.equals(ECConstants.ZERO));

            BigInteger var13 = var6.getD();
            BigInteger var14 = ((ECPrivateKeyParameters)var9.getPrivate()).getD();
            var8 = var14.subtract(var7.multiply(var13)).mod(var2);
            BigInteger[] var15 = new BigInteger[]{var7, var8};
            return var15;
         }
      }
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      if (this.forSigning) {
         throw new IllegalStateException("not initialised for verifying");
      } else {
         ECPublicKeyParameters var4 = (ECPublicKeyParameters)this.key;
         BigInteger var5 = var4.getParameters().getN();
         int var6 = var5.bitLength();
         BigInteger var7 = new BigInteger(1, var1);
         int var8 = var7.bitLength();
         if (var8 > var6) {
            throw new DataLengthException("input too large for ECNR key.");
         } else if (var2.compareTo(ECConstants.ONE) >= 0 && var2.compareTo(var5) < 0) {
            if (var3.compareTo(ECConstants.ZERO) >= 0 && var3.compareTo(var5) < 0) {
               ECPoint var9 = var4.getParameters().getG();
               ECPoint var10 = var4.getQ();
               ECPoint var11 = ECAlgorithms.sumOfTwoMultiplies(var9, var3, var10, var2);
               BigInteger var12 = var11.getX().toBigInteger();
               BigInteger var13 = var2.subtract(var12).mod(var5);
               return var13.equals(var7);
            } else {
               return false;
            }
         } else {
            return false;
         }
      }
   }
}
