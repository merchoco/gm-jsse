package org.bc.crypto.agreement;

import java.math.BigInteger;
import org.bc.crypto.BasicAgreement;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.MQVPrivateParameters;
import org.bc.crypto.params.MQVPublicParameters;
import org.bc.math.ec.ECAlgorithms;
import org.bc.math.ec.ECConstants;
import org.bc.math.ec.ECPoint;

public class ECMQVBasicAgreement implements BasicAgreement {
   MQVPrivateParameters privParams;

   public void init(CipherParameters var1) {
      this.privParams = (MQVPrivateParameters)var1;
   }

   public int getFieldSize() {
      return (this.privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
   }

   public BigInteger calculateAgreement(CipherParameters var1) {
      MQVPublicParameters var2 = (MQVPublicParameters)var1;
      ECPrivateKeyParameters var3 = this.privParams.getStaticPrivateKey();
      ECPoint var4 = this.calculateMqvAgreement(var3.getParameters(), var3, this.privParams.getEphemeralPrivateKey(), this.privParams.getEphemeralPublicKey(), var2.getStaticPublicKey(), var2.getEphemeralPublicKey());
      return var4.getX().toBigInteger();
   }

   private ECPoint calculateMqvAgreement(ECDomainParameters var1, ECPrivateKeyParameters var2, ECPrivateKeyParameters var3, ECPublicKeyParameters var4, ECPublicKeyParameters var5, ECPublicKeyParameters var6) {
      BigInteger var7 = var1.getN();
      int var8 = (var7.bitLength() + 1) / 2;
      BigInteger var9 = ECConstants.ONE.shiftLeft(var8);
      ECPoint var10;
      if (var4 == null) {
         var10 = var1.getG().multiply(var3.getD());
      } else {
         var10 = var4.getQ();
      }

      BigInteger var11 = var10.getX().toBigInteger();
      BigInteger var12 = var11.mod(var9);
      BigInteger var13 = var12.setBit(var8);
      BigInteger var14 = var2.getD().multiply(var13).mod(var7).add(var3.getD()).mod(var7);
      BigInteger var15 = var6.getQ().getX().toBigInteger();
      BigInteger var16 = var15.mod(var9);
      BigInteger var17 = var16.setBit(var8);
      BigInteger var18 = var1.getH().multiply(var14).mod(var7);
      ECPoint var19 = ECAlgorithms.sumOfTwoMultiplies(var5.getQ(), var17.multiply(var18).mod(var7), var6.getQ(), var18);
      if (var19.isInfinity()) {
         throw new IllegalStateException("Infinity is not a valid agreement value for MQV");
      } else {
         return var19;
      }
   }
}
