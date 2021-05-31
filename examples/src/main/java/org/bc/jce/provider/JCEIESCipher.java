package org.bc.jce.provider;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.agreement.DHBasicAgreement;
import org.bc.crypto.agreement.ECDHBasicAgreement;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.engines.IESEngine;
import org.bc.crypto.generators.KDF2BytesGenerator;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.IESParameters;
import org.bc.jcajce.provider.asymmetric.ec.ECUtil;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.interfaces.IESKey;
import org.bc.jce.spec.IESParameterSpec;

public class JCEIESCipher extends CipherSpi {
   private IESEngine cipher;
   private int state = -1;
   private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
   private AlgorithmParameters engineParam = null;
   private IESParameterSpec engineParams = null;
   private Class[] availableSpecs = new Class[]{IESParameterSpec.class};

   public JCEIESCipher(IESEngine var1) {
      this.cipher = var1;
   }

   protected int engineGetBlockSize() {
      return 0;
   }

   protected byte[] engineGetIV() {
      return null;
   }

   protected int engineGetKeySize(Key var1) {
      if (!(var1 instanceof IESKey)) {
         throw new IllegalArgumentException("must be passed IE key");
      } else {
         IESKey var2 = (IESKey)var1;
         if (var2.getPrivate() instanceof DHPrivateKey) {
            DHPrivateKey var4 = (DHPrivateKey)var2.getPrivate();
            return var4.getX().bitLength();
         } else if (var2.getPrivate() instanceof ECPrivateKey) {
            ECPrivateKey var3 = (ECPrivateKey)var2.getPrivate();
            return var3.getD().bitLength();
         } else {
            throw new IllegalArgumentException("not an IE key!");
         }
      }
   }

   protected int engineGetOutputSize(int var1) {
      if (this.state != 1 && this.state != 3) {
         if (this.state != 2 && this.state != 4) {
            throw new IllegalStateException("cipher not initialised");
         } else {
            return this.buffer.size() + var1 - 20;
         }
      } else {
         return this.buffer.size() + var1 + 20;
      }
   }

   protected AlgorithmParameters engineGetParameters() {
      if (this.engineParam == null && this.engineParams != null) {
         String var1 = "IES";

         try {
            this.engineParam = AlgorithmParameters.getInstance(var1, BouncyCastleProvider.PROVIDER_NAME);
            this.engineParam.init(this.engineParams);
         } catch (Exception var3) {
            throw new RuntimeException(var3.toString());
         }
      }

      return this.engineParam;
   }

   protected void engineSetMode(String var1) {
      throw new IllegalArgumentException("can't support mode " + var1);
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      throw new NoSuchPaddingException(var1 + " unavailable with RSA.");
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (!(var2 instanceof IESKey)) {
         throw new InvalidKeyException("must be passed IES key");
      } else {
         if (var3 == null && (var1 == 1 || var1 == 3)) {
            byte[] var5 = new byte[16];
            byte[] var6 = new byte[16];
            if (var4 == null) {
               var4 = new SecureRandom();
            }

            var4.nextBytes(var5);
            var4.nextBytes(var6);
            var3 = new IESParameterSpec(var5, var6, 128);
         } else if (!(var3 instanceof IESParameterSpec)) {
            throw new InvalidAlgorithmParameterException("must be passed IES parameters");
         }

         IESKey var9 = (IESKey)var2;
         AsymmetricKeyParameter var7;
         AsymmetricKeyParameter var10;
         if (var9.getPublic() instanceof ECPublicKey) {
            var10 = ECUtil.generatePublicKeyParameter(var9.getPublic());
            var7 = ECUtil.generatePrivateKeyParameter(var9.getPrivate());
         } else {
            var10 = DHUtil.generatePublicKeyParameter(var9.getPublic());
            var7 = DHUtil.generatePrivateKeyParameter(var9.getPrivate());
         }

         this.engineParams = (IESParameterSpec)var3;
         IESParameters var8 = new IESParameters(this.engineParams.getDerivationV(), this.engineParams.getEncodingV(), this.engineParams.getMacKeySize());
         this.state = var1;
         this.buffer.reset();
         switch(var1) {
         case 1:
         case 3:
            this.cipher.init(true, var7, var10, var8);
            break;
         case 2:
         case 4:
            this.cipher.init(false, var7, var10, var8);
            break;
         default:
            System.out.println("eeek!");
         }

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

      this.engineParam = var3;
      this.engineInit(var1, var2, var5, var4);
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      if (var1 == 1 || var1 == 3) {
         try {
            this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
            return;
         } catch (InvalidAlgorithmParameterException var5) {
            ;
         }
      }

      throw new IllegalArgumentException("can't handle null parameter spec in IES");
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      this.buffer.write(var1, var2, var3);
      return null;
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.buffer.write(var1, var2, var3);
      return 0;
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      if (var3 != 0) {
         this.buffer.write(var1, var2, var3);
      }

      try {
         byte[] var4 = this.buffer.toByteArray();
         this.buffer.reset();
         return this.cipher.processBlock(var4, 0, var4.length);
      } catch (InvalidCipherTextException var5) {
         throw new BadPaddingException(var5.getMessage());
      }
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException, BadPaddingException {
      if (var3 != 0) {
         this.buffer.write(var1, var2, var3);
      }

      try {
         byte[] var6 = this.buffer.toByteArray();
         this.buffer.reset();
         var6 = this.cipher.processBlock(var6, 0, var6.length);
         System.arraycopy(var6, 0, var4, var5, var6.length);
         return var6.length;
      } catch (InvalidCipherTextException var7) {
         throw new BadPaddingException(var7.getMessage());
      }
   }

   public static class BrokenECIES extends JCEIESCipher {
      public BrokenECIES() {
         super(new IESEngine(new ECDHBasicAgreement(), new BrokenKDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
      }
   }

   public static class BrokenIES extends JCEIESCipher {
      public BrokenIES() {
         super(new IESEngine(new DHBasicAgreement(), new BrokenKDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
      }
   }

   public static class IES extends JCEIESCipher {
      public IES() {
         super(new IESEngine(new DHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
      }
   }
}
