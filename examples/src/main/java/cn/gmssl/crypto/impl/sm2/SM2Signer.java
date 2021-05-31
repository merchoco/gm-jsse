package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.engines.MyBigInteger;
import org.bc.crypto.params.ECKeyParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.math.ec.ECPoint;

public class SM2Signer implements DSA {
   private ECKeyParameters key = null;
   private SecureRandom secureRandom = null;
   private static final BigInteger ZERO = BigInteger.valueOf(0L);
   private static final BigInteger ONE = BigInteger.valueOf(1L);

   public void init(boolean var1, CipherParameters var2) {
      if (var1) {
         if (var2 instanceof ParametersWithRandom) {
            ParametersWithRandom var3 = (ParametersWithRandom)var2;
            this.secureRandom = var3.getRandom();
            this.key = (ECPrivateKeyParameters)var3.getParameters();
         } else {
            try {
               this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
            } catch (Exception var4) {
               throw new RuntimeException(var4);
            }

            this.key = (ECPrivateKeyParameters)var2;
         }
      } else {
         this.key = (ECPublicKeyParameters)var2;
      }

   }

   public BigInteger[] generateSignature(byte[] var1) {
      BigInteger var2 = this.key.getParameters().getN();
      BigInteger var3 = ((ECPrivateKeyParameters)this.key).getD();
      ECPoint var4 = this.key.getParameters().getG();
      BigInteger var5 = new BigInteger(1, var1);
      if (Debug.sm2) {
         PrintUtil.printHex(var5, "e");
      }

      BigInteger var6 = null;
      BigInteger var7 = null;
      BigInteger var8 = null;

      while(true) {
         var7 = MyBigInteger.gen(var2, this.secureRandom);
         ECPoint var9 = var4.multiply(var7);
         BigInteger var10 = var9.getX().toBigInteger();
         if (Debug.sm2) {
            PrintUtil.printHex(var10, "x1");
         }

         var6 = var5.add(var10).mod(var2);
         if (Debug.sm2) {
            PrintUtil.printHex(var6, "r");
         }

         if (!var6.equals(ZERO) && !var6.add(var7).equals(var2)) {
            if (Debug.sm2) {
               PrintUtil.printHex(ONE.add(var3).modInverse(var2), "(1+dA)逆");
            }

            var8 = ONE.add(var3).modInverse(var2).multiply(var7.subtract(var6.multiply(var3))).mod(var2);
            if (!var8.equals(ZERO)) {
               if (Debug.sm2) {
                  PrintUtil.printHex(var8, "s");
               }

               BigInteger[] var11 = new BigInteger[]{var6, var8};
               return var11;
            }
         }
      }
   }

   public boolean verifySignature(byte[] var1, BigInteger var2, BigInteger var3) {
      if (Debug.sm2) {
         PrintUtil.printHex(var1, "message");
         System.out.println("message end");
      }

      BigInteger var4 = this.key.getParameters().getN();
      ECPoint var5 = this.key.getParameters().getG();
      ECPoint var6 = ((ECPublicKeyParameters)this.key).getQ();
      if (var2.compareTo(ONE) >= 0 && var2.compareTo(var4) < 0) {
         if (var3.compareTo(ONE) >= 0 && var3.compareTo(var4) < 0) {
            BigInteger var7 = new BigInteger(1, var1);
            if (Debug.sm2) {
               PrintUtil.printHex(var7, "e");
            }

            BigInteger var8 = var2.add(var3).mod(var4);
            if (var8.equals(ZERO)) {
               return false;
            } else {
               if (Debug.sm2) {
                  PrintUtil.printHex(var8, "t");
               }

               ECPoint var9 = var5.multiply(var3);
               ECPoint var10 = var6.multiply(var8);
               BigInteger var11 = var9.getX().toBigInteger();
               BigInteger var12 = var10.getX().toBigInteger();
               BigInteger var13 = var9.add(var10).getX().toBigInteger();
               BigInteger var14 = var7.add(var13).mod(var4);
               if (Debug.sm2) {
                  PrintUtil.printHex(var11, "x0'");
                  PrintUtil.printHex(var12, "x00'");
                  PrintUtil.printHex(var13, "x1'");
                  PrintUtil.printHex(var14, "R");
               }

               return var14.equals(var2);
            }
         } else {
            return false;
         }
      } else {
         return false;
      }
   }
}
