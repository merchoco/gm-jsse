package org.bc.jcajce.provider.asymmetric.rsa;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.engines.RSABlindedEngine;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.signers.ISO9796d2Signer;

public class ISOSignatureSpi extends SignatureSpi {
   private ISO9796d2Signer signer;

   protected ISOSignatureSpi(Digest var1, AsymmetricBlockCipher var2) {
      this.signer = new ISO9796d2Signer(var2, var1, true);
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      RSAKeyParameters var2 = RSAUtil.generatePublicKeyParameter((RSAPublicKey)var1);
      this.signer.init(false, var2);
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      RSAKeyParameters var2 = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)var1);
      this.signer.init(true, var2);
   }

   protected void engineUpdate(byte var1) throws SignatureException {
      this.signer.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
      this.signer.update(var1, var2, var3);
   }

   protected byte[] engineSign() throws SignatureException {
      try {
         byte[] var1 = this.signer.generateSignature();
         return var1;
      } catch (Exception var2) {
         throw new SignatureException(var2.toString());
      }
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      boolean var2 = this.signer.verifySignature(var1);
      return var2;
   }

   protected void engineSetParameter(AlgorithmParameterSpec var1) {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   /** @deprecated */
   protected void engineSetParameter(String var1, Object var2) {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   /** @deprecated */
   protected Object engineGetParameter(String var1) {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   public static class MD5WithRSAEncryption extends ISOSignatureSpi {
      public MD5WithRSAEncryption() {
         super(new MD5Digest(), new RSABlindedEngine());
      }
   }

   public static class RIPEMD160WithRSAEncryption extends ISOSignatureSpi {
      public RIPEMD160WithRSAEncryption() {
         super(new RIPEMD160Digest(), new RSABlindedEngine());
      }
   }

   public static class SHA1WithRSAEncryption extends ISOSignatureSpi {
      public SHA1WithRSAEncryption() {
         super(new SHA1Digest(), new RSABlindedEngine());
      }
   }
}
