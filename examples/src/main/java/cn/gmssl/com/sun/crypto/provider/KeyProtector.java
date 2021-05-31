package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.SealedObject;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class KeyProtector {
   private static final String PBE_WITH_MD5_AND_DES3_CBC_OID = "1.3.6.1.4.1.42.2.19.1";
   private static final String KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1";
   private static final int SALT_LEN = 20;
   private static final int DIGEST_LEN = 20;
   private char[] password;
   private static final Provider PROV = Security.getProvider("SunJCE");

   KeyProtector(char[] var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("password can't be null");
      } else {
         this.password = var1;
      }
   }

   byte[] protect(PrivateKey var1) throws Exception {
      byte[] var2 = new byte[8];
      SunJCE.RANDOM.nextBytes(var2);
      PBEParameterSpec var3 = new PBEParameterSpec(var2, 20);
      PBEKeySpec var4 = new PBEKeySpec(this.password);
      PBEKey var5 = new PBEKey(var4, "PBEWithMD5AndTripleDES");
      var4.clearPassword();
      PBEWithMD5AndTripleDESCipher var6 = new PBEWithMD5AndTripleDESCipher();
      var6.engineInit(1, var5, (AlgorithmParameterSpec)var3, (SecureRandom)null);
      byte[] var7 = var1.getEncoded();
      byte[] var8 = var6.engineDoFinal(var7, 0, var7.length);
      AlgorithmParameters var9 = AlgorithmParameters.getInstance("PBE", PROV);
      var9.init(var3);
      AlgorithmId var10 = new AlgorithmId(new ObjectIdentifier("1.3.6.1.4.1.42.2.19.1"), var9);
      return (new EncryptedPrivateKeyInfo(var10, var8)).getEncoded();
   }

   Key recover(EncryptedPrivateKeyInfo var1) throws UnrecoverableKeyException, NoSuchAlgorithmException {
      try {
         String var3 = var1.getAlgorithm().getOID().toString();
         if (!var3.equals("1.3.6.1.4.1.42.2.19.1") && !var3.equals("1.3.6.1.4.1.42.2.17.1.1")) {
            throw new UnrecoverableKeyException("Unsupported encryption algorithm");
         } else {
            byte[] var2;
            if (var3.equals("1.3.6.1.4.1.42.2.17.1.1")) {
               var2 = this.recover(var1.getEncryptedData());
            } else {
               byte[] var4 = var1.getAlgorithm().getEncodedParams();
               AlgorithmParameters var5 = AlgorithmParameters.getInstance("PBE");
               var5.init(var4);
               PBEParameterSpec var6 = (PBEParameterSpec)var5.getParameterSpec(PBEParameterSpec.class);
               PBEKeySpec var7 = new PBEKeySpec(this.password);
               PBEKey var8 = new PBEKey(var7, "PBEWithMD5AndTripleDES");
               var7.clearPassword();
               PBEWithMD5AndTripleDESCipher var9 = new PBEWithMD5AndTripleDESCipher();
               var9.engineInit(2, var8, (AlgorithmParameterSpec)var6, (SecureRandom)null);
               var2 = var9.engineDoFinal(var1.getEncryptedData(), 0, var1.getEncryptedData().length);
            }

            String var13 = (new AlgorithmId((new PrivateKeyInfo(var2)).getAlgorithm().getOID())).getName();
            KeyFactory var14 = KeyFactory.getInstance(var13);
            return var14.generatePrivate(new PKCS8EncodedKeySpec(var2));
         }
      } catch (NoSuchAlgorithmException var10) {
         throw var10;
      } catch (IOException var11) {
         throw new UnrecoverableKeyException(var11.getMessage());
      } catch (GeneralSecurityException var12) {
         throw new UnrecoverableKeyException(var12.getMessage());
      }
   }

   private byte[] recover(byte[] var1) throws UnrecoverableKeyException, NoSuchAlgorithmException {
      MessageDigest var8 = MessageDigest.getInstance("SHA");
      byte[] var9 = new byte[20];
      System.arraycopy(var1, 0, var9, 0, 20);
      int var7 = var1.length - 20 - 20;
      int var5 = var7 / 20;
      if (var7 % 20 != 0) {
         ++var5;
      }

      byte[] var10 = new byte[var7];
      System.arraycopy(var1, 20, var10, 0, var7);
      byte[] var11 = new byte[var10.length];
      byte[] var12 = new byte[this.password.length * 2];
      int var2 = 0;

      for(int var3 = 0; var2 < this.password.length; ++var2) {
         var12[var3++] = (byte)(this.password[var2] >> 8);
         var12[var3++] = (byte)this.password[var2];
      }

      var2 = 0;
      int var6 = 0;

      byte[] var4;
      for(var4 = var9; var2 < var5; var6 += 20) {
         var8.update(var12);
         var8.update(var4);
         var4 = var8.digest();
         var8.reset();
         if (var2 < var5 - 1) {
            System.arraycopy(var4, 0, var11, var6, var4.length);
         } else {
            System.arraycopy(var4, 0, var11, var6, var11.length - var6);
         }

         ++var2;
      }

      byte[] var13 = new byte[var10.length];

      for(var2 = 0; var2 < var13.length; ++var2) {
         var13[var2] = (byte)(var10[var2] ^ var11[var2]);
      }

      var8.update(var12);
      Arrays.fill(var12, (byte)0);
      Object var14 = null;
      var8.update(var13);
      var4 = var8.digest();
      var8.reset();

      for(var2 = 0; var2 < var4.length; ++var2) {
         if (var4[var2] != var1[20 + var7 + var2]) {
            throw new UnrecoverableKeyException("Cannot recover key");
         }
      }

      return var13;
   }

   SealedObject seal(Key var1) throws Exception {
      byte[] var2 = new byte[8];
      SunJCE.RANDOM.nextBytes(var2);
      PBEParameterSpec var3 = new PBEParameterSpec(var2, 20);
      PBEKeySpec var4 = new PBEKeySpec(this.password);
      PBEKey var5 = new PBEKey(var4, "PBEWithMD5AndTripleDES");
      var4.clearPassword();
      PBEWithMD5AndTripleDESCipher var7 = new PBEWithMD5AndTripleDESCipher();
      CipherForKeyProtector var6 = new CipherForKeyProtector(var7, PROV, "PBEWithMD5AndTripleDES");
      var6.init(1, var5, var3);
      return new SealedObjectForKeyProtector(var1, var6);
   }

   Key unseal(SealedObject var1) throws NoSuchAlgorithmException, UnrecoverableKeyException {
      try {
         PBEKeySpec var2 = new PBEKeySpec(this.password);
         PBEKey var3 = new PBEKey(var2, "PBEWithMD5AndTripleDES");
         var2.clearPassword();
         SealedObjectForKeyProtector var4 = null;
         if (!(var1 instanceof SealedObjectForKeyProtector)) {
            var4 = new SealedObjectForKeyProtector(var1);
         } else {
            var4 = (SealedObjectForKeyProtector)var1;
         }

         AlgorithmParameters var5 = var4.getParameters();
         if (var5 == null) {
            throw new UnrecoverableKeyException("Cannot get algorithm parameters");
         } else {
            PBEWithMD5AndTripleDESCipher var6 = new PBEWithMD5AndTripleDESCipher();
            CipherForKeyProtector var7 = new CipherForKeyProtector(var6, PROV, "PBEWithMD5AndTripleDES");
            var7.init(2, var3, var5);
            return (Key)var4.getObject(var7);
         }
      } catch (NoSuchAlgorithmException var8) {
         throw var8;
      } catch (IOException var9) {
         throw new UnrecoverableKeyException(var9.getMessage());
      } catch (ClassNotFoundException var10) {
         throw new UnrecoverableKeyException(var10.getMessage());
      } catch (GeneralSecurityException var11) {
         throw new UnrecoverableKeyException(var11.getMessage());
      }
   }
}
