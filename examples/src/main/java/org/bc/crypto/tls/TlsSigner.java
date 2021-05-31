package org.bc.crypto.tls;

import java.security.SecureRandom;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Signer;
import org.bc.crypto.params.AsymmetricKeyParameter;

interface TlsSigner {
   byte[] calculateRawSignature(SecureRandom var1, AsymmetricKeyParameter var2, byte[] var3) throws CryptoException;

   Signer createVerifyer(AsymmetricKeyParameter var1);

   boolean isValidPublicKey(AsymmetricKeyParameter var1);
}
