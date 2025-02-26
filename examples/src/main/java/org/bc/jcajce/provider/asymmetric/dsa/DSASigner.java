package org.bc.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAKey;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DSA;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.NullDigest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;

public class DSASigner extends SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
   private Digest digest;
   private DSA signer;
   private SecureRandom random;

   protected DSASigner(Digest var1, DSA var2) {
      this.digest = var1;
      this.signer = var2;
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2;
      if (var1 instanceof DSAKey) {
         var2 = DSAUtil.generatePublicKeyParameter(var1);
      } else {
         try {
            byte[] var3 = var1.getEncoded();
            BCDSAPublicKey var5 = new BCDSAPublicKey(SubjectPublicKeyInfo.getInstance(var3));
            if (!(var5 instanceof DSAKey)) {
               throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }

            var2 = DSAUtil.generatePublicKeyParameter(var5);
         } catch (Exception var4) {
            throw new InvalidKeyException("can't recognise key type in DSA based signer");
         }
      }

      this.digest.reset();
      this.signer.init(false, var2);
   }

   protected void engineInitSign(PrivateKey var1, SecureRandom var2) throws InvalidKeyException {
      this.random = var2;
      this.engineInitSign(var1);
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      Object var2 = DSAUtil.generatePrivateKeyParameter(var1);
      if (this.random != null) {
         var2 = new ParametersWithRandom((CipherParameters)var2, this.random);
      }

      this.digest.reset();
      this.signer.init(true, (CipherParameters)var2);
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
         return this.derEncode(var2[0], var2[1]);
      } catch (Exception var3) {
         throw new SignatureException(var3.toString());
      }
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      byte[] var2 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var2, 0);

      BigInteger[] var3;
      try {
         var3 = this.derDecode(var1);
      } catch (Exception var5) {
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

   private byte[] derEncode(BigInteger var1, BigInteger var2) throws IOException {
      ASN1Integer[] var3 = new ASN1Integer[]{new ASN1Integer(var1), new ASN1Integer(var2)};
      return (new DERSequence(var3)).getEncoded("DER");
   }

   private BigInteger[] derDecode(byte[] var1) throws IOException {
      ASN1Sequence var2 = (ASN1Sequence)ASN1Primitive.fromByteArray(var1);
      return new BigInteger[]{((ASN1Integer)var2.getObjectAt(0)).getValue(), ((ASN1Integer)var2.getObjectAt(1)).getValue()};
   }

   public static class dsa224 extends DSASigner {
      public dsa224() {
         super(new SHA224Digest(), new org.bc.crypto.signers.DSASigner());
      }
   }

   public static class dsa256 extends DSASigner {
      public dsa256() {
         super(new SHA256Digest(), new org.bc.crypto.signers.DSASigner());
      }
   }

   public static class dsa384 extends DSASigner {
      public dsa384() {
         super(new SHA384Digest(), new org.bc.crypto.signers.DSASigner());
      }
   }

   public static class dsa512 extends DSASigner {
      public dsa512() {
         super(new SHA512Digest(), new org.bc.crypto.signers.DSASigner());
      }
   }

   public static class noneDSA extends DSASigner {
      public noneDSA() {
         super(new NullDigest(), new org.bc.crypto.signers.DSASigner());
      }
   }

   public static class stdDSA extends DSASigner {
      public stdDSA() {
         super(new SHA1Digest(), new org.bc.crypto.signers.DSASigner());
      }
   }
}
