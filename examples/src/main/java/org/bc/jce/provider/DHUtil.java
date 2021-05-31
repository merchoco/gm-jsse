package org.bc.jce.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;

public class DHUtil {
   public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey var0) throws InvalidKeyException {
      if (var0 instanceof DHPublicKey) {
         DHPublicKey var1 = (DHPublicKey)var0;
         return new DHPublicKeyParameters(var1.getY(), new DHParameters(var1.getParams().getP(), var1.getParams().getG(), (BigInteger)null, var1.getParams().getL()));
      } else {
         throw new InvalidKeyException("can't identify DH public key.");
      }
   }

   public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey var0) throws InvalidKeyException {
      if (var0 instanceof DHPrivateKey) {
         DHPrivateKey var1 = (DHPrivateKey)var0;
         return new DHPrivateKeyParameters(var1.getX(), new DHParameters(var1.getParams().getP(), var1.getParams().getG(), (BigInteger)null, var1.getParams().getL()));
      } else {
         throw new InvalidKeyException("can't identify DH private key.");
      }
   }
}
