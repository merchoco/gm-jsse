package org.bc.crypto.tls;

import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Signer;
import org.bc.crypto.digests.NullDigest;
import org.bc.crypto.encodings.PKCS1Encoding;
import org.bc.crypto.engines.RSABlindedEngine;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.signers.GenericSigner;

class TlsRSASigner implements TlsSigner {
   public byte[] calculateRawSignature(SecureRandom var1, AsymmetricKeyParameter var2, byte[] var3) throws CryptoException {
      GenericSigner var4 = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new NullDigest());
      var4.init(true, new ParametersWithRandom(var2, var1));
      var4.update(var3, 0, var3.length);
      return var4.generateSignature();
   }

   public Signer createVerifyer(AsymmetricKeyParameter var1) {
      GenericSigner var2 = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), new CombinedHash());
      var2.init(false, var1);
      return var2;
   }

   public boolean isValidPublicKey(AsymmetricKeyParameter var1) {
      return var1 instanceof RSAKeyParameters && !var1.isPrivate();
   }
}
