package org.bc.crypto.tls;

import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.DSA;
import org.bc.crypto.Signer;
import org.bc.crypto.digests.NullDigest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.signers.DSADigestSigner;

abstract class TlsDSASigner implements TlsSigner {
   public byte[] calculateRawSignature(SecureRandom var1, AsymmetricKeyParameter var2, byte[] var3) throws CryptoException {
      DSADigestSigner var4 = new DSADigestSigner(this.createDSAImpl(), new NullDigest());
      var4.init(true, new ParametersWithRandom(var2, var1));
      var4.update(var3, 16, 20);
      return var4.generateSignature();
   }

   public Signer createVerifyer(AsymmetricKeyParameter var1) {
      DSADigestSigner var2 = new DSADigestSigner(this.createDSAImpl(), new SHA1Digest());
      var2.init(false, var1);
      return var2;
   }

   protected abstract DSA createDSAImpl();
}
