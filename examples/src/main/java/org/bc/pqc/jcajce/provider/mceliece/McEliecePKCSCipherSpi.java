package org.bc.pqc.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.pqc.crypto.mceliece.McElieceKeyParameters;
import org.bc.pqc.crypto.mceliece.McEliecePKCSCipher;
import org.bc.pqc.jcajce.provider.util.AsymmetricBlockCipher;

public class McEliecePKCSCipherSpi extends AsymmetricBlockCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
   private Digest digest;
   private McEliecePKCSCipher cipher;

   public McEliecePKCSCipherSpi(Digest var1, McEliecePKCSCipher var2) {
      this.digest = var1;
      this.cipher = var2;
   }

   protected void initCipherEncrypt(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AsymmetricKeyParameter var4 = McElieceKeysToParams.generatePublicKeyParameter((PublicKey)var1);
      ParametersWithRandom var5 = new ParametersWithRandom(var4, var3);
      this.digest.reset();
      this.cipher.init(true, var5);
      this.maxPlainTextSize = this.cipher.maxPlainTextSize;
      this.cipherTextSize = this.cipher.cipherTextSize;
   }

   protected void initCipherDecrypt(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AsymmetricKeyParameter var3 = McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)var1);
      this.digest.reset();
      this.cipher.init(false, var3);
      this.maxPlainTextSize = this.cipher.maxPlainTextSize;
      this.cipherTextSize = this.cipher.cipherTextSize;
   }

   protected byte[] messageEncrypt(byte[] var1) throws IllegalBlockSizeException, BadPaddingException {
      byte[] var2 = null;

      try {
         var2 = this.cipher.messageEncrypt(var1);
      } catch (Exception var4) {
         var4.printStackTrace();
      }

      return var2;
   }

   protected byte[] messageDecrypt(byte[] var1) throws IllegalBlockSizeException, BadPaddingException {
      byte[] var2 = null;

      try {
         var2 = this.cipher.messageDecrypt(var1);
      } catch (Exception var4) {
         var4.printStackTrace();
      }

      return var2;
   }

   public String getName() {
      return "McEliecePKCS";
   }

   public int getKeySize(Key var1) throws InvalidKeyException {
      McElieceKeyParameters var2;
      if (var1 instanceof PublicKey) {
         var2 = (McElieceKeyParameters)McElieceKeysToParams.generatePublicKeyParameter((PublicKey)var1);
      } else {
         var2 = (McElieceKeyParameters)McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)var1);
      }

      return this.cipher.getKeySize(var2);
   }

   public static class McEliecePKCS extends McEliecePKCSCipherSpi {
      public McEliecePKCS() {
         super(new SHA1Digest(), new McEliecePKCSCipher());
      }
   }

   public static class McEliecePKCS224 extends McEliecePKCSCipherSpi {
      public McEliecePKCS224() {
         super(new SHA224Digest(), new McEliecePKCSCipher());
      }
   }

   public static class McEliecePKCS256 extends McEliecePKCSCipherSpi {
      public McEliecePKCS256() {
         super(new SHA256Digest(), new McEliecePKCSCipher());
      }
   }

   public static class McEliecePKCS384 extends McEliecePKCSCipherSpi {
      public McEliecePKCS384() {
         super(new SHA384Digest(), new McEliecePKCSCipher());
      }
   }

   public static class McEliecePKCS512 extends McEliecePKCSCipherSpi {
      public McEliecePKCS512() {
         super(new SHA512Digest(), new McEliecePKCSCipher());
      }
   }
}
