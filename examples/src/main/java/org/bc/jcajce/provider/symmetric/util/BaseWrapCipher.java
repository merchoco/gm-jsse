package org.bc.jcajce.provider.symmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.Wrapper;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.jce.provider.BouncyCastleProvider;

public abstract class BaseWrapCipher extends CipherSpi implements PBE {
   private Class[] availableSpecs;
   protected int pbeType;
   protected int pbeHash;
   protected int pbeKeySize;
   protected int pbeIvSize;
   protected AlgorithmParameters engineParams;
   protected Wrapper wrapEngine;
   private int ivSize;
   private byte[] iv;

   protected BaseWrapCipher() {
      this.availableSpecs = new Class[]{IvParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class};
      this.pbeType = 2;
      this.pbeHash = 1;
      this.engineParams = null;
      this.wrapEngine = null;
   }

   protected BaseWrapCipher(Wrapper var1) {
      this(var1, 0);
   }

   protected BaseWrapCipher(Wrapper var1, int var2) {
      this.availableSpecs = new Class[]{IvParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class};
      this.pbeType = 2;
      this.pbeHash = 1;
      this.engineParams = null;
      this.wrapEngine = null;
      this.wrapEngine = var1;
      this.ivSize = var2;
   }

   protected int engineGetBlockSize() {
      return 0;
   }

   protected byte[] engineGetIV() {
      return (byte[])this.iv.clone();
   }

   protected int engineGetKeySize(Key var1) {
      return var1.getEncoded().length;
   }

   protected int engineGetOutputSize(int var1) {
      return -1;
   }

   protected AlgorithmParameters engineGetParameters() {
      return null;
   }

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      throw new NoSuchAlgorithmException("can't support mode " + var1);
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      throw new NoSuchPaddingException("Padding " + var1 + " unknown.");
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      Object var5;
      if (var2 instanceof BCPBEKey) {
         BCPBEKey var6 = (BCPBEKey)var2;
         if (var3 instanceof PBEParameterSpec) {
            var5 = PBE.Util.makePBEParameters(var6, var3, this.wrapEngine.getAlgorithmName());
         } else {
            if (var6.getParam() == null) {
               throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
            }

            var5 = var6.getParam();
         }
      } else {
         var5 = new KeyParameter(var2.getEncoded());
      }

      if (var3 instanceof IvParameterSpec) {
         IvParameterSpec var7 = (IvParameterSpec)var3;
         var5 = new ParametersWithIV((CipherParameters)var5, var7.getIV());
      }

      if (var5 instanceof KeyParameter && this.ivSize != 0) {
         this.iv = new byte[this.ivSize];
         var4.nextBytes(this.iv);
         var5 = new ParametersWithIV((CipherParameters)var5, this.iv);
      }

      switch(var1) {
      case 1:
      case 2:
         throw new IllegalArgumentException("engine only valid for wrapping");
      case 3:
         this.wrapEngine.init(true, (CipherParameters)var5);
         break;
      case 4:
         this.wrapEngine.init(false, (CipherParameters)var5);
         break;
      default:
         System.out.println("eeek!");
      }

   }

   protected void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AlgorithmParameterSpec var5 = null;
      if (var3 != null) {
         int var6 = 0;

         while(var6 != this.availableSpecs.length) {
            try {
               var5 = var3.getParameterSpec(this.availableSpecs[var6]);
               break;
            } catch (Exception var8) {
               ++var6;
            }
         }

         if (var5 == null) {
            throw new InvalidAlgorithmParameterException("can't handle parameter " + var3.toString());
         }
      }

      this.engineParams = var3;
      this.engineInit(var1, var2, var5, var4);
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new IllegalArgumentException(var5.getMessage());
      }
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      throw new RuntimeException("not supported for wrapping");
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      throw new RuntimeException("not supported for wrapping");
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      return null;
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
      return 0;
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 == null) {
         throw new InvalidKeyException("Cannot wrap key, null encoding.");
      } else {
         try {
            return this.wrapEngine == null ? this.engineDoFinal(var2, 0, var2.length) : this.wrapEngine.wrap(var2, 0, var2.length);
         } catch (BadPaddingException var4) {
            throw new IllegalBlockSizeException(var4.getMessage());
         }
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException, NoSuchAlgorithmException {
      byte[] var4;
      try {
         if (this.wrapEngine == null) {
            var4 = this.engineDoFinal(var1, 0, var1.length);
         } else {
            var4 = this.wrapEngine.unwrap(var1, 0, var1.length);
         }
      } catch (InvalidCipherTextException var8) {
         throw new InvalidKeyException(var8.getMessage());
      } catch (BadPaddingException var9) {
         throw new InvalidKeyException(var9.getMessage());
      } catch (IllegalBlockSizeException var10) {
         throw new InvalidKeyException(var10.getMessage());
      }

      if (var3 == 3) {
         return new SecretKeySpec(var4, var2);
      } else if (var2.equals("") && var3 == 2) {
         try {
            PrivateKeyInfo var13 = PrivateKeyInfo.getInstance(var4);
            PrivateKey var6 = BouncyCastleProvider.getPrivateKey(var13);
            if (var6 != null) {
               return var6;
            } else {
               throw new InvalidKeyException("algorithm " + var13.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
            }
         } catch (Exception var7) {
            var7.printStackTrace();
            throw new InvalidKeyException("Invalid key encoding.");
         }
      } else {
         try {
            KeyFactory var5 = KeyFactory.getInstance(var2, BouncyCastleProvider.PROVIDER_NAME);
            if (var3 == 1) {
               return var5.generatePublic(new X509EncodedKeySpec(var4));
            }

            if (var3 == 2) {
               return var5.generatePrivate(new PKCS8EncodedKeySpec(var4));
            }
         } catch (NoSuchProviderException var11) {
            throw new InvalidKeyException("Unknown key type " + var11.getMessage());
         } catch (InvalidKeySpecException var12) {
            throw new InvalidKeyException("Unknown key type " + var12.getMessage());
         }

         throw new InvalidKeyException("Unknown key type " + var3);
      }
   }
}
