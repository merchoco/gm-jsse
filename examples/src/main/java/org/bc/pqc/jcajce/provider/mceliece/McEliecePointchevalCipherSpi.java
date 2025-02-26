package org.bc.pqc.jcajce.provider.mceliece;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
import org.bc.pqc.crypto.mceliece.McElieceCCA2KeyParameters;
import org.bc.pqc.crypto.mceliece.McEliecePointchevalCipher;
import org.bc.pqc.jcajce.provider.util.AsymmetricHybridCipher;

public class McEliecePointchevalCipherSpi extends AsymmetricHybridCipher implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
   private Digest digest;
   private McEliecePointchevalCipher cipher;
   private ByteArrayOutputStream buf = new ByteArrayOutputStream();

   protected McEliecePointchevalCipherSpi(Digest var1, McEliecePointchevalCipher var2) {
      this.digest = var1;
      this.cipher = var2;
      this.buf = new ByteArrayOutputStream();
   }

   public byte[] update(byte[] var1, int var2, int var3) {
      this.buf.write(var1, var2, var3);
      return new byte[0];
   }

   public byte[] doFinal(byte[] var1, int var2, int var3) throws BadPaddingException {
      this.update(var1, var2, var3);
      byte[] var4 = this.buf.toByteArray();
      this.buf.reset();
      if (this.opMode == 1) {
         try {
            return this.cipher.messageEncrypt(var4);
         } catch (Exception var7) {
            var7.printStackTrace();
         }
      } else if (this.opMode == 2) {
         try {
            return this.cipher.messageDecrypt(var4);
         } catch (Exception var6) {
            var6.printStackTrace();
         }
      }

      return null;
   }

   protected int encryptOutputSize(int var1) {
      return 0;
   }

   protected int decryptOutputSize(int var1) {
      return 0;
   }

   protected void initCipherEncrypt(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AsymmetricKeyParameter var4 = McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)var1);
      ParametersWithRandom var5 = new ParametersWithRandom(var4, var3);
      this.digest.reset();
      this.cipher.init(true, var5);
   }

   protected void initCipherDecrypt(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AsymmetricKeyParameter var3 = McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)var1);
      this.digest.reset();
      this.cipher.init(false, var3);
   }

   public String getName() {
      return "McEliecePointchevalCipher";
   }

   public int getKeySize(Key var1) throws InvalidKeyException {
      McElieceCCA2KeyParameters var2;
      if (var1 instanceof PublicKey) {
         var2 = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePublicKeyParameter((PublicKey)var1);
      } else {
         var2 = (McElieceCCA2KeyParameters)McElieceCCA2KeysToParams.generatePrivateKeyParameter((PrivateKey)var1);
      }

      return this.cipher.getKeySize(var2);
   }

   public byte[] messageEncrypt(byte[] var1) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
      byte[] var2 = null;

      try {
         var2 = this.cipher.messageEncrypt(var1);
      } catch (Exception var4) {
         var4.printStackTrace();
      }

      return var2;
   }

   public byte[] messageDecrypt(byte[] var1) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
      byte[] var2 = null;

      try {
         var2 = this.cipher.messageDecrypt(var1);
      } catch (Exception var4) {
         var4.printStackTrace();
      }

      return var2;
   }

   public static class McEliecePointcheval extends McEliecePointchevalCipherSpi {
      public McEliecePointcheval() {
         super(new SHA1Digest(), new McEliecePointchevalCipher());
      }
   }

   public static class McEliecePointcheval224 extends McEliecePointchevalCipherSpi {
      public McEliecePointcheval224() {
         super(new SHA224Digest(), new McEliecePointchevalCipher());
      }
   }

   public static class McEliecePointcheval256 extends McEliecePointchevalCipherSpi {
      public McEliecePointcheval256() {
         super(new SHA256Digest(), new McEliecePointchevalCipher());
      }
   }

   public static class McEliecePointcheval384 extends McEliecePointchevalCipherSpi {
      public McEliecePointcheval384() {
         super(new SHA384Digest(), new McEliecePointchevalCipher());
      }
   }

   public static class McEliecePointcheval512 extends McEliecePointchevalCipherSpi {
      public McEliecePointcheval512() {
         super(new SHA512Digest(), new McEliecePointchevalCipher());
      }
   }
}
