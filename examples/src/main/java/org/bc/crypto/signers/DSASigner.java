package org.bc.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.params.DSAKeyParameters;
import org.bc.crypto.params.DSAParameters;
import org.bc.crypto.params.DSAPrivateKeyParameters;
import org.bc.crypto.params.DSAPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;

public class DSASigner implements DSA {
   DSAKeyParameters key;
   SecureRandom random;

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.random = var3.getRandom();
            this.key = (DSAPrivateKeyParameters)var3.getParameters();
         } else {
            this.random = new SecureRandom();
            this.key = (DSAPrivateKeyParameters)var2;
         }
      } else {
         this.key = (DSAPublicKeyParameters)var2;
      }

   }

   public BigInteger[] generateSignature(byte[] var1) {
      DSAParameters var2 = this.key.getParameters();
      BigInteger var3 = this.calculateE(var2.getQ(), var1);
      int var5 = var2.getQ().bitLength();

      BigInteger var4;
      do {
         var4 = new BigInteger(var5, this.random);
      } while(var4.compareTo(var2.getQ()) >= 0);

      BigInteger var6 = var2.getG().modPow(var4, var2.getP()).mod(var2.getQ());
      var4 = var4.modInverse(var2.getQ()).multiply(var3.add(((DSAPrivateKeyParameters)this.key).getX().multiply(var6)));
      BigInteger var7 = var4.mod(var2.getQ());
      BigInteger[] var8 = new BigInteger[]{var6, var7};
      return var8;
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      DSAParameters var4 = this.key.getParameters();
      BigInteger var5 = this.calculateE(var4.getQ(), var1);
      BigInteger var6 = BigInteger.valueOf(0L);
      if (var6.compareTo(var2) < 0 && var4.getQ().compareTo(var2) > 0) {
         if (var6.compareTo(var3) < 0 && var4.getQ().compareTo(var3) > 0) {
            BigInteger var7 = var3.modInverse(var4.getQ());
            BigInteger var8 = var5.multiply(var7).mod(var4.getQ());
            BigInteger var9 = var2.multiply(var7).mod(var4.getQ());
            var8 = var4.getG().modPow(var8, var4.getP());
            var9 = ((DSAPublicKeyParameters)this.key).getY().modPow(var9, var4.getP());
            BigInteger var10 = var8.multiply(var9).mod(var4.getP()).mod(var4.getQ());
            return var10.equals(var2);
         } else {
            return false;
         }
      } else {
         return false;
      }
   }

   private BigInteger calculateE(BigInteger var1, byte[] var2) {
      if (var1.bitLength() >= var2.length * 8) {
         return new BigInteger(1, var2);
      } else {
         byte[] var3 = new byte[var1.bitLength() / 8];
         System.arraycopy(var2, 0, var3, 0, var3.length);
         return new BigInteger(1, var3);
      }
   }
}
