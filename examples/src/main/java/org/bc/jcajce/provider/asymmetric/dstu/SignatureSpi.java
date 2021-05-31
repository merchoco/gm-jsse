package org.bc.jcajce.provider.asymmetric.dstu;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.crypto.DSA;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.GOST3411Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.signers.DSTU4145Signer;
import org.bc.jcajce.provider.asymmetric.ec.ECUtil;
import org.bc.jce.interfaces.ECKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.provider.BouncyCastleProvider;

public class SignatureSpi extends java.security.SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
   private Digest digest;
   private DSA signer = new DSTU4145Signer();
   private static byte[] DEFAULT_SBOX = new byte[]{10, 9, 13, 6, 14, 11, 4, 5, 15, 1, 3, 12, 7, 0, 8, 2, 8, 0, 12, 4, 9, 6, 7, 11, 2, 3, 1, 15, 5, 14, 10, 13, 15, 6, 5, 8, 14, 11, 10, 4, 12, 0, 3, 7, 2, 9, 1, 13, 3, 8, 13, 9, 6, 11, 15, 0, 2, 5, 12, 10, 4, 14, 1, 7, 15, 8, 14, 9, 7, 2, 0, 13, 12, 6, 1, 5, 11, 4, 3, 10, 2, 8, 9, 7, 5, 15, 0, 11, 12, 1, 13, 14, 10, 3, 6, 4, 3, 8, 11, 5, 6, 4, 14, 10, 2, 12, 1, 7, 9, 15, 13, 0, 1, 2, 3, 14, 6, 13, 11, 8, 15, 10, 12, 5, 7, 9, 0, 4};

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2;
      if (var1 instanceof ECPublicKey) {
         var2 = ECUtil.generatePublicKeyParameter(var1);
      } else {
         try {
            byte[] var3 = var1.getEncoded();
            var1 = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(var3));
            if (!(var1 instanceof ECPublicKey)) {
               throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }

            var2 = ECUtil.generatePublicKeyParameter(var1);
         } catch (Exception var4) {
            throw new InvalidKeyException("can't recognise key type in DSA based signer");
         }
      }

      this.digest = new GOST3411Digest(this.expandSbox(((BCDSTU4145PublicKey)var1).getSbox()));
      this.signer.init(false, var2);
   }

   byte[] expandSbox(byte[] var1) {
      byte[] var2 = new byte[128];

      for(int var3 = 0; var3 < var1.length; ++var3) {
         var2[var3 * 2] = (byte)(var1[var3] >> 4 & 15);
         var2[var3 * 2 + 1] = (byte)(var1[var3] & 15);
      }

      return var2;
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2 = null;
      if (var1 instanceof ECKey) {
         var2 = ECUtil.generatePrivateKeyParameter(var1);
      }

      this.digest = new GOST3411Digest(DEFAULT_SBOX);
      if (this.appRandom != null) {
         this.signer.init(true, new ParametersWithRandom(var2, this.appRandom));
      } else {
         this.signer.init(true, var2);
      }

   }

   protected void engineUpdate(byte var1) throws SignatureException {
      this.digest.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
      this.digest.update(var1, var2, var3);
   }

   protected byte[] engineSign() throws SignatureException {
      byte[] var1 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var1, 0);

      try {
         BigInteger[] var2 = this.signer.generateSignature(var1);
         byte[] var3 = var2[0].toByteArray();
         byte[] var4 = var2[1].toByteArray();
         byte[] var5 = new byte[var3.length > var4.length ? var3.length * 2 : var4.length * 2];
         System.arraycopy(var4, 0, var5, var5.length / 2 - var4.length, var4.length);
         System.arraycopy(var3, 0, var5, var5.length - var3.length, var4.length);
         return (new DEROctetString(var5)).getEncoded();
      } catch (Exception var6) {
         throw new SignatureException(var6.toString());
      }
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      byte[] var2 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var2, 0);

      BigInteger[] var3;
      try {
         byte[] var4 = ((ASN1OctetString)ASN1OctetString.fromByteArray(var1)).getOctets();
         byte[] var5 = new byte[var4.length / 2];
         byte[] var6 = new byte[var4.length / 2];
         System.arraycopy(var4, 0, var6, 0, var4.length / 2);
         System.arraycopy(var4, var4.length / 2, var5, 0, var4.length / 2);
         var3 = new BigInteger[]{new BigInteger(1, var5), new BigInteger(1, var6)};
      } catch (Exception var7) {
         throw new SignatureException("error decoding signature bytes.");
      }

      return this.signer.verifySignature(var2, var3[0], var3[1]);
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
}
