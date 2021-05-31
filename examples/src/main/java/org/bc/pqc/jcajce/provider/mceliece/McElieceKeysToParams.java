package org.bc.pqc.jcajce.provider.mceliece;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bc.pqc.crypto.mceliece.McEliecePublicKeyParameters;

public class McElieceKeysToParams {
   public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey var0) throws InvalidKeyException {
      if (var0 instanceof BCMcEliecePublicKey) {
         BCMcEliecePublicKey var1 = (BCMcEliecePublicKey)var0;
         return new McEliecePublicKeyParameters(var1.getOIDString(), var1.getN(), var1.getT(), var1.getG(), var1.getMcElieceParameters());
      } else {
         throw new InvalidKeyException("can't identify McEliece public key: " + var0.getClass().getName());
      }
   }

   public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey var0) throws InvalidKeyException {
      if (var0 instanceof BCMcEliecePrivateKey) {
         BCMcEliecePrivateKey var1 = (BCMcEliecePrivateKey)var0;
         return new McEliecePrivateKeyParameters(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getSInv(), var1.getP1(), var1.getP2(), var1.getH(), var1.getQInv(), var1.getMcElieceParameters());
      } else {
         throw new InvalidKeyException("can't identify McEliece private key.");
      }
   }
}
