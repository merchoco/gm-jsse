package org.bc.jcajce.provider.asymmetric.ec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.KeyEncoder;
import org.bc.crypto.KeyParser;
import org.bc.crypto.agreement.ECDHBasicAgreement;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.engines.AESEngine;
import org.bc.crypto.engines.DESedeEngine;
import org.bc.crypto.engines.IESEngine;
import org.bc.crypto.generators.ECKeyPairGenerator;
import org.bc.crypto.generators.EphemeralKeyPairGenerator;
import org.bc.crypto.generators.KDF2BytesGenerator;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.paddings.PaddedBufferedBlockCipher;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.params.IESWithCipherParameters;
import org.bc.crypto.parsers.ECIESPublicKeyParser;
import org.bc.jcajce.provider.asymmetric.util.IESUtil;
import org.bc.jce.interfaces.ECKey;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.interfaces.IESKey;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.IESParameterSpec;
import org.bc.util.Strings;

public class IESCipher extends CipherSpi {
   private IESEngine engine;
   private int state = -1;
   private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
   private AlgorithmParameters engineParam = null;
   private IESParameterSpec engineSpec = null;
   private AsymmetricKeyParameter key;
   private SecureRandom random;
   private boolean dhaesMode = false;
   private AsymmetricKeyParameter otherKeyParameter = null;

   public IESCipher(IESEngine var1) {
      this.engine = var1;
   }

   public int engineGetBlockSize() {
      return this.engine.getCipher() != null ? this.engine.getCipher().getBlockSize() : 0;
   }

   public int engineGetKeySize(Key var1) {
      if (var1 instanceof ECKey) {
         return ((ECKey)var1).getParameters().getCurve().getFieldSize();
      } else {
         throw new IllegalArgumentException("not an EC key");
      }
   }

   public byte[] engineGetIV() {
      return null;
   }

   public AlgorithmParameters engineGetParameters() {
      if (this.engineParam == null && this.engineSpec != null) {
         try {
            this.engineParam = AlgorithmParameters.getInstance("IES", BouncyCastleProvider.PROVIDER_NAME);
            this.engineParam.init(this.engineSpec);
         } catch (Exception var2) {
            throw new RuntimeException(var2.toString());
         }
      }

      return this.engineParam;
   }

   public void engineSetMode(String var1) throws NoSuchAlgorithmException {
      String var2 = Strings.toUpperCase(var1);
      if (var2.equals("NONE")) {
         this.dhaesMode = false;
      } else {
         if (!var2.equals("DHAES")) {
            throw new IllegalArgumentException("can't support mode " + var1);
         }

         this.dhaesMode = true;
      }

   }

   public int engineGetOutputSize(int var1) {
      int var2 = this.engine.getMac().getMacSize();
      if (this.key == null) {
         throw new IllegalStateException("cipher not initialised");
      } else {
         int var3 = 1 + 2 * (((ECKey)this.key).getParameters().getCurve().getFieldSize() + 7) / 8;
         int var4;
         if (this.engine.getCipher() == null) {
            var4 = var1;
         } else if (this.state != 1 && this.state != 3) {
            if (this.state != 2 && this.state != 4) {
               throw new IllegalStateException("cipher not initialised");
            }

            var4 = this.engine.getCipher().getOutputSize(var1 - var2 - var3);
         } else {
            var4 = this.engine.getCipher().getOutputSize(var1);
         }

         if (this.state != 1 && this.state != 3) {
            if (this.state != 2 && this.state != 4) {
               throw new IllegalStateException("cipher not initialised");
            } else {
               return this.buffer.size() - var2 - var3 + var4;
            }
         } else {
            return this.buffer.size() + var2 + var3 + var4;
         }
      }
   }

   public void engineSetPadding(String var1) throws NoSuchPaddingException {
      String var2 = Strings.toUpperCase(var1);
      if (!var2.equals("NOPADDING") && !var2.equals("PKCS5PADDING") && !var2.equals("PKCS7PADDING")) {
         throw new NoSuchPaddingException("padding not available with IESCipher");
      }
   }

   public void engineInit(int var1, Key var2, AlgorithmParameters var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AlgorithmParameterSpec var5 = null;
      if (var3 != null) {
         try {
            var5 = var3.getParameterSpec(IESParameterSpec.class);
         } catch (Exception var7) {
            throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + var7.toString());
         }
      }

      this.engineParam = var3;
      this.engineInit(var1, var2, var5, var4);
   }

   public void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidAlgorithmParameterException, InvalidKeyException {
      this.otherKeyParameter = null;
      if (var3 == null) {
         this.engineSpec = IESUtil.guessParameterSpec(this.engine);
      } else {
         if (!(var3 instanceof IESParameterSpec)) {
            throw new InvalidAlgorithmParameterException("must be passed IES parameters");
         }

         this.engineSpec = (IESParameterSpec)var3;
      }

      IESKey var5;
      if (var1 != 1 && var1 != 3) {
         if (var1 != 2 && var1 != 4) {
            throw new InvalidKeyException("must be passed EC key");
         }

         if (var2 instanceof ECPrivateKey) {
            this.key = ECUtil.generatePrivateKeyParameter((PrivateKey)var2);
         } else {
            if (!(var2 instanceof IESKey)) {
               throw new InvalidKeyException("must be passed recipient's private EC key for decryption");
            }

            var5 = (IESKey)var2;
            this.otherKeyParameter = ECUtil.generatePublicKeyParameter(var5.getPublic());
            this.key = ECUtil.generatePrivateKeyParameter(var5.getPrivate());
         }
      } else if (var2 instanceof ECPublicKey) {
         this.key = ECUtil.generatePublicKeyParameter((PublicKey)var2);
      } else {
         if (!(var2 instanceof IESKey)) {
            throw new InvalidKeyException("must be passed recipient's public EC key for encryption");
         }

         var5 = (IESKey)var2;
         this.key = ECUtil.generatePublicKeyParameter(var5.getPublic());
         this.otherKeyParameter = ECUtil.generatePrivateKeyParameter(var5.getPrivate());
      }

      this.random = var4;
      this.state = var1;
      this.buffer.reset();
   }

   public void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new IllegalArgumentException("can't handle supplied parameter spec");
      }
   }

   public byte[] engineUpdate(byte[] var1, int var2, int var3) {
      this.buffer.write(var1, var2, var3);
      return null;
   }

   public int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      this.buffer.write(var1, var2, var3);
      return 0;
   }

   public byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      if (var3 != 0) {
         this.buffer.write(var1, var2, var3);
      }

      byte[] var4 = this.buffer.toByteArray();
      this.buffer.reset();
      IESWithCipherParameters var5 = new IESWithCipherParameters(this.engineSpec.getDerivationV(), this.engineSpec.getEncodingV(), this.engineSpec.getMacKeySize(), this.engineSpec.getCipherKeySize());
      ECDomainParameters var6 = ((ECKeyParameters)this.key).getParameters();
      if (this.otherKeyParameter == null) {
         if (this.state != 1 && this.state != 3) {
            if (this.state != 2 && this.state != 4) {
               throw new IllegalStateException("cipher not initialised");
            } else {
               try {
                  this.engine.init(this.key, var5, (KeyParser)(new ECIESPublicKeyParser(var6)));
                  return this.engine.processBlock(var4, 0, var4.length);
               } catch (InvalidCipherTextException var11) {
                  throw new BadPaddingException(var11.getMessage());
               }
            }
         } else {
            ECKeyPairGenerator var8 = new ECKeyPairGenerator();
            var8.init(new ECKeyGenerationParameters(var6, this.random));
            EphemeralKeyPairGenerator var9 = new EphemeralKeyPairGenerator(var8, new KeyEncoder() {
               public byte[] getEncoded(AsymmetricKeyParameter var1) {
                  return ((ECPublicKeyParameters)var1).getQ().getEncoded();
               }
            });

            try {
               this.engine.init(this.key, var5, (EphemeralKeyPairGenerator)var9);
               return this.engine.processBlock(var4, 0, var4.length);
            } catch (Exception var12) {
               throw new BadPaddingException(var12.getMessage());
            }
         }
      } else {
         try {
            if (this.state != 1 && this.state != 3) {
               this.engine.init(false, this.key, this.otherKeyParameter, var5);
            } else {
               this.engine.init(true, this.otherKeyParameter, this.key, var5);
            }

            return this.engine.processBlock(var4, 0, var4.length);
         } catch (Exception var13) {
            throw new BadPaddingException(var13.getMessage());
         }
      }
   }

   public int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      byte[] var6 = this.engineDoFinal(var1, var2, var3);
      System.arraycopy(var6, 0, var4, var5, var6.length);
      return var6.length;
   }

   public static class ECIES extends IESCipher {
      public ECIES() {
         super(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest())));
      }
   }

   public static class ECIESwithAES extends IESCipher {
      public ECIESwithAES() {
         super(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), new PaddedBufferedBlockCipher(new AESEngine())));
      }
   }

   public static class ECIESwithDESede extends IESCipher {
      public ECIESwithDESede() {
         super(new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA1Digest()), new HMac(new SHA1Digest()), new PaddedBufferedBlockCipher(new DESedeEngine())));
      }
   }
}
