package org.bc.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.agreement.DHBasicAgreement;
import org.bc.crypto.generators.DHBasicKeyPairGenerator;
import org.bc.crypto.params.DHKeyGenerationParameters;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.util.BigIntegers;

public class TlsDHUtils {
   static final BigInteger ONE = BigInteger.valueOf(1L);
   static final BigInteger TWO = BigInteger.valueOf(2L);

   public static byte[] calculateDHBasicAgreement(DHPublicKeyParameters var0, DHPrivateKeyParameters var1) {
      DHBasicAgreement var2 = new DHBasicAgreement();
      var2.init(var1);
      BigInteger var3 = var2.calculateAgreement(var0);
      return BigIntegers.asUnsignedByteArray(var3);
   }

   public static AsymmetricCipherKeyPair generateDHKeyPair(SecureRandom var0, DHParameters var1) {
      DHBasicKeyPairGenerator var2 = new DHBasicKeyPairGenerator();
      var2.init(new DHKeyGenerationParameters(var0, var1));
      return var2.generateKeyPair();
   }

   public static DHPrivateKeyParameters generateEphemeralClientKeyExchange(SecureRandom var0, DHParameters var1, OutputStream var2) throws IOException {
      AsymmetricCipherKeyPair var3 = generateDHKeyPair(var0, var1);
      DHPrivateKeyParameters var4 = (DHPrivateKeyParameters)var3.getPrivate();
      BigInteger var5 = ((DHPublicKeyParameters)var3.getPublic()).getY();
      byte[] var6 = BigIntegers.asUnsignedByteArray(var5);
      TlsUtils.writeOpaque16(var6, var2);
      return var4;
   }

   public static DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters var0) throws IOException {
      BigInteger var1 = var0.getY();
      DHParameters var2 = var0.getParameters();
      BigInteger var3 = var2.getP();
      BigInteger var4 = var2.getG();
      if (!var3.isProbablePrime(2)) {
         throw new TlsFatalAlert((short)47);
      } else if (var4.compareTo(TWO) >= 0 && var4.compareTo(var3.subtract(TWO)) <= 0) {
         if (var1.compareTo(TWO) >= 0 && var1.compareTo(var3.subtract(ONE)) <= 0) {
            return var0;
         } else {
            throw new TlsFatalAlert((short)47);
         }
      } else {
         throw new TlsFatalAlert((short)47);
      }
   }
}
