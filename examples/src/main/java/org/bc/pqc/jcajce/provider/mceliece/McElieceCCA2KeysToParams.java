package org.bc.pqc.jcajce.provider.mceliece;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;

public class McElieceCCA2KeysToParams {
   public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey var0) throws InvalidKeyException {
      if (var0 instanceof BCMcElieceCCA2PublicKey) {
         BCMcElieceCCA2PublicKey var1 = (BCMcElieceCCA2PublicKey)var0;
         return new McElieceCCA2PublicKeyParameters(var1.getOIDString(), var1.getN(), var1.getT(), var1.getG(), var1.getMcElieceCCA2Parameters());
      } else {
         throw new InvalidKeyException("can't identify McElieceCCA2 public key: " + var0.getClass().getName());
      }
   }

   public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey var0) throws InvalidKeyException {
      if (var0 instanceof BCMcElieceCCA2PrivateKey) {
         BCMcElieceCCA2PrivateKey var1 = (BCMcElieceCCA2PrivateKey)var0;
         return new McElieceCCA2PrivateKeyParameters(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getP(), var1.getH(), var1.getQInv(), var1.getMcElieceCCA2Parameters());
      } else {
         throw new InvalidKeyException("can't identify McElieceCCA2 private key.");
      }
   }
}
