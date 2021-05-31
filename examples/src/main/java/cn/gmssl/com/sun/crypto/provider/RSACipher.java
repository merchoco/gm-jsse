package cn.gmssl.com.sun.crypto.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import sun.security.jca.Providers;
import sun.security.rsa.RSACore;
import sun.security.rsa.RSAKeyFactory;
import sun.security.rsa.RSAPadding;

public final class RSACipher extends CipherSpi {
   private static final byte[] B0 = new byte[0];
   private static final int MODE_ENCRYPT = 1;
   private static final int MODE_DECRYPT = 2;
   private static final int MODE_SIGN = 3;
   private static final int MODE_VERIFY = 4;
   private static final String PAD_NONE = "NoPadding";
   private static final String PAD_PKCS1 = "PKCS1Padding";
   private static final String PAD_OAEP_MGF1 = "OAEP";
   private int mode;
   private String paddingType = "PKCS1Padding";
   private RSAPadding padding;
   private OAEPParameterSpec spec = null;
   private byte[] buffer;
   private int bufOfs;
   private int outputSize;
   private RSAPublicKey publicKey;
   private RSAPrivateKey privateKey;
   private String oaepHashAlgorithm = "SHA-1";

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      if (!var1.equalsIgnoreCase("ECB")) {
         throw new NoSuchAlgorithmException("Unsupported mode " + var1);
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (var1.equalsIgnoreCase("NoPadding")) {
         this.paddingType = "NoPadding";
      } else if (var1.equalsIgnoreCase("PKCS1Padding")) {
         this.paddingType = "PKCS1Padding";
      } else {
         String var2 = var1.toLowerCase(Locale.ENGLISH);
         if (var2.equals("oaeppadding")) {
            this.paddingType = "OAEP";
         } else {
            if (!var2.startsWith("oaepwith") || !var2.endsWith("andmgf1padding")) {
               throw new NoSuchPaddingException("Padding " + var1 + " not supported");
            }

            this.paddingType = "OAEP";
            this.oaepHashAlgorithm = var1.substring(8, var1.length() - 14);
            if (Providers.getProviderList().getService("MessageDigest", this.oaepHashAlgorithm) == null) {
               throw new NoSuchPaddingException("MessageDigest not available for " + var1);
            }
         }
      }

   }

   protected int engineGetBlockSize() {
      return 0;
   }

   protected int engineGetOutputSize(int var1) {
      return this.outputSize;
   }

   protected byte[] engineGetIV() {
      return null;
   }

   protected AlgorithmParameters engineGetParameters() {
      if (this.spec != null) {
         try {
            AlgorithmParameters var1 = AlgorithmParameters.getInstance("OAEP", "SunJCE");
            var1.init(this.spec);
            return var1;
         } catch (NoSuchAlgorithmException var2) {
            throw new RuntimeException("Cannot find OAEP  AlgorithmParameters implementation in SunJCE provider");
         } catch (NoSuchProviderException var3) {
            throw new RuntimeException("Cannot find SunJCE provider");
         } catch (InvalidParameterSpecException var4) {
            throw new RuntimeException("OAEPParameterSpec not supported");
         }
      } else {
         return null;
      }
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.init(var1, var2, var3, (AlgorithmParameterSpec)null);
      } catch (InvalidAlgorithmParameterException var6) {
         InvalidKeyException var5 = new InvalidKeyException("Wrong parameters");
         var5.initCause(var6);
         throw var5;
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.init(var1, var2, var4, var3);
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var3 == null) {
         this.init(var1, var2, var4, (AlgorithmParameterSpec)null);
      } else {
         try {
            OAEPParameterSpec var5 = (OAEPParameterSpec)var3.getParameterSpec(OAEPParameterSpec.class);
            this.init(var1, var2, var4, var5);
         } catch (InvalidParameterSpecException var7) {
            InvalidAlgorithmParameterException var6 = new InvalidAlgorithmParameterException("Wrong parameter");
            var6.initCause(var7);
            throw var6;
         }
      }

   }

   private void init(int var1, Key var2, SecureRandom var3, AlgorithmParameterSpec var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      boolean var5;
      switch(var1) {
      case 1:
      case 3:
         var5 = true;
         break;
      case 2:
      case 4:
         var5 = false;
         break;
      default:
         throw new InvalidKeyException("Unknown mode: " + var1);
      }

      RSAKey var6 = RSAKeyFactory.toRSAKey(var2);
      if (var2 instanceof RSAPublicKey) {
         this.mode = var5 ? 1 : 4;
         this.publicKey = (RSAPublicKey)var2;
         this.privateKey = null;
      } else {
         this.mode = var5 ? 3 : 2;
         this.privateKey = (RSAPrivateKey)var2;
         this.publicKey = null;
      }

      int var7 = RSACore.getByteLength(var6.getModulus());
      this.outputSize = var7;
      this.bufOfs = 0;
      if (this.paddingType == "NoPadding") {
         if (var4 != null) {
            throw new InvalidAlgorithmParameterException("Parameters not supported");
         }

         this.padding = RSAPadding.getInstance(3, var7, var3);
         this.buffer = new byte[var7];
      } else {
         int var9;
         if (this.paddingType == "PKCS1Padding") {
            if (var4 != null) {
               throw new InvalidAlgorithmParameterException("Parameters not supported");
            }

            int var10 = this.mode <= 2 ? 2 : 1;
            this.padding = RSAPadding.getInstance(var10, var7, var3);
            if (var5) {
               var9 = this.padding.getMaxDataSize();
               this.buffer = new byte[var9];
            } else {
               this.buffer = new byte[var7];
            }
         } else {
            if (this.mode == 3 || this.mode == 4) {
               throw new InvalidKeyException("OAEP cannot be used to sign or verify signatures");
            }

            OAEPParameterSpec var8;
            if (var4 != null) {
               if (!(var4 instanceof OAEPParameterSpec)) {
                  throw new InvalidAlgorithmParameterException("Wrong Parameters for OAEP Padding");
               }

               var8 = (OAEPParameterSpec)var4;
            } else {
               var8 = new OAEPParameterSpec(this.oaepHashAlgorithm, "MGF1", MGF1ParameterSpec.SHA1, PSpecified.DEFAULT);
            }

            this.padding = RSAPadding.getInstance(4, var7, var3, var8);
            if (var5) {
               var9 = this.padding.getMaxDataSize();
               this.buffer = new byte[var9];
            } else {
               this.buffer = new byte[var7];
            }
         }
      }

   }

   private void update(byte[] var1, int var2, int var3) {
      if (var3 != 0 && var1 != null) {
         if (this.bufOfs + var3 > this.buffer.length) {
            this.bufOfs = this.buffer.length + 1;
         } else {
            System.arraycopy(var1, var2, this.buffer, this.bufOfs, var3);
            this.bufOfs += var3;
         }
      }
   }

   private byte[] doFinal() throws BadPaddingException, IllegalBlockSizeException {
      if (this.bufOfs > this.buffer.length) {
         throw new IllegalBlockSizeException("Data must not be longer than " + this.buffer.length + " bytes");
      } else {
         try {
            byte[] var1;
            byte[] var5;
            switch(this.mode) {
            case 1:
               var1 = this.padding.pad(this.buffer, 0, this.bufOfs);
               var5 = RSACore.rsa(var1, this.publicKey);
               return var5;
            case 2:
               byte[] var3 = RSACore.convert(this.buffer, 0, this.bufOfs);
               var1 = RSACore.rsa(var3, this.privateKey);
               var5 = this.padding.unpad(var1);
               return var5;
            case 3:
               var1 = this.padding.pad(this.buffer, 0, this.bufOfs);
               var5 = RSACore.rsa(var1, this.privateKey);
               return var5;
            case 4:
               byte[] var2 = RSACore.convert(this.buffer, 0, this.bufOfs);
               var1 = RSACore.rsa(var2, this.publicKey);
               var5 = this.padding.unpad(var1);
               return var5;
            default:
               throw new AssertionError("Internal error");
            }
         } finally {
            this.bufOfs = 0;
         }
      }
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      this.update(var1, var2, var3);
      return B0;
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.update(var1, var2, var3);
      return 0;
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws BadPaddingException, IllegalBlockSizeException {
      this.update(var1, var2, var3);
      return this.doFinal();
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, BadPaddingException, IllegalBlockSizeException {
      if (this.outputSize > var4.length - var5) {
         throw new ShortBufferException("Need " + this.outputSize + " bytes for output");
      } else {
         this.update(var1, var2, var3);
         byte[] var6 = this.doFinal();
         int var7 = var6.length;
         System.arraycopy(var6, 0, var4, var5, var7);
         return var7;
      }
   }

   protected byte[] engineWrap(Key var1) throws InvalidKeyException, IllegalBlockSizeException {
      byte[] var2 = var1.getEncoded();
      if (var2 != null && var2.length != 0) {
         if (var2.length > this.buffer.length) {
            throw new InvalidKeyException("Key is too long for wrapping");
         } else {
            this.update(var2, 0, var2.length);

            try {
               return this.doFinal();
            } catch (BadPaddingException var4) {
               throw new InvalidKeyException("Wrapping failed", var4);
            }
         }
      } else {
         throw new InvalidKeyException("Could not obtain encoded key");
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      if (var1.length > this.buffer.length) {
         throw new InvalidKeyException("Key is too long for unwrapping");
      } else {
         this.update(var1, 0, var1.length);

         try {
            byte[] var4 = this.doFinal();
            return ConstructKeys.constructKey(var4, var2, var3);
         } catch (BadPaddingException var5) {
            throw new InvalidKeyException("Unwrapping failed", var5);
         } catch (IllegalBlockSizeException var6) {
            throw new InvalidKeyException("Unwrapping failed", var6);
         }
      }
   }

   protected int engineGetKeySize(Key var1) throws InvalidKeyException {
      RSAKey var2 = RSAKeyFactory.toRSAKey(var1);
      return var2.getModulus().bitLength();
   }
}
