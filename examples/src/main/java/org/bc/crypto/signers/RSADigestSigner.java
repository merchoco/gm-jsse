package org.bc.crypto.signers;

import java.io.IOException;
import java.util.Hashtable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERNull;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DigestInfo;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.CryptoException;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.Digest;
import org.bc.crypto.Signer;
import org.bc.crypto.encodings.PKCS1Encoding;
import org.bc.crypto.engines.RSABlindedEngine;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.util.Arrays;

public class RSADigestSigner implements Signer {
   private final AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
   private final AlgorithmIdentifier algId;
   private final Digest digest;
   private boolean forSigning;
   private static final Hashtable oidMap = new Hashtable();

   static {
      oidMap.put("RIPEMD128", TeleTrusTObjectIdentifiers.ripemd128);
      oidMap.put("RIPEMD160", TeleTrusTObjectIdentifiers.ripemd160);
      oidMap.put("RIPEMD256", TeleTrusTObjectIdentifiers.ripemd256);
      oidMap.put("SHA-1", X509ObjectIdentifiers.id_SHA1);
      oidMap.put("SHA-224", NISTObjectIdentifiers.id_sha224);
      oidMap.put("SHA-256", NISTObjectIdentifiers.id_sha256);
      oidMap.put("SHA-384", NISTObjectIdentifiers.id_sha384);
      oidMap.put("SHA-512", NISTObjectIdentifiers.id_sha512);
      oidMap.put("MD2", PKCSObjectIdentifiers.md2);
      oidMap.put("MD4", PKCSObjectIdentifiers.md4);
      oidMap.put("MD5", PKCSObjectIdentifiers.md5);
   }

   public RSADigestSigner(Digest var1) {
      this.digest = var1;
      this.algId = new AlgorithmIdentifier((ASN1ObjectIdentifier)oidMap.get(var1.getAlgorithmName()), DERNull.INSTANCE);
   }

   /** @deprecated */
   public String getAlgorithmName() {
      return this.digest.getAlgorithmName() + "withRSA";
   }

   public void init(boolean var1, CipherParameters var2) {
      this.forSigning = var1;
      AsymmetricKeyParameter var3;
      if (var2 instanceof ParametersWithRandom) {
         var3 = (AsymmetricKeyParameter)((ParametersWithRandom)var2).getParameters();
      } else {
         var3 = (AsymmetricKeyParameter)var2;
      }

      if (var1 && !var3.isPrivate()) {
         throw new IllegalArgumentException("signing requires private key");
      } else if (!var1 && var3.isPrivate()) {
         throw new IllegalArgumentException("verification requires public key");
      } else {
         this.reset();
         this.rsaEngine.init(var1, var2);
      }
   }

   public void update(byte var1) {
      this.digest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.digest.update(var1, var2, var3);
   }

   public byte[] generateSignature() throws CryptoException, DataLengthException {
      if (!this.forSigning) {
         throw new IllegalStateException("RSADigestSigner not initialised for signature generation.");
      } else {
         byte[] var1 = new byte[this.digest.getDigestSize()];
         this.digest.doFinal(var1, 0);

         try {
            byte[] var2 = this.derEncode(var1);
            return this.rsaEngine.processBlock(var2, 0, var2.length);
         } catch (IOException var3) {
            throw new CryptoException("unable to encode signature: " + var3.getMessage(), var3);
         }
      }
   }

   public boolean verifySignature(byte[] var1) {
      if (this.forSigning) {
         throw new IllegalStateException("RSADigestSigner not initialised for verification");
      } else {
         byte[] var2 = new byte[this.digest.getDigestSize()];
         this.digest.doFinal(var2, 0);

         byte[] var3;
         byte[] var4;
         try {
            var3 = this.rsaEngine.processBlock(var1, 0, var1.length);
            var4 = this.derEncode(var2);
         } catch (Exception var9) {
            return false;
         }

         if (var3.length == var4.length) {
            return Arrays.constantTimeAreEqual(var3, var4);
         } else if (var3.length != var4.length - 2) {
            return false;
         } else {
            int var5 = var3.length - var2.length - 2;
            int var6 = var4.length - var2.length - 2;
            var4[1] = (byte)(var4[1] - 2);
            var4[3] = (byte)(var4[3] - 2);
            int var7 = 0;

            int var8;
            for(var8 = 0; var8 < var2.length; ++var8) {
               var7 |= var3[var5 + var8] ^ var4[var6 + var8];
            }

            for(var8 = 0; var8 < var5; ++var8) {
               var7 |= var3[var8] ^ var4[var8];
            }

            return var7 == 0;
         }
      }
   }

   public void reset() {
      this.digest.reset();
   }

   private byte[] derEncode(byte[] var1) throws IOException {
      DigestInfo var2 = new DigestInfo(this.algId, var1);
      return var2.getEncoded("DER");
   }
}
