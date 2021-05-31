package org.bc.jce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
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
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.BufferedBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.OutputLengthException;
import org.bc.crypto.engines.AESFastEngine;
import org.bc.crypto.engines.DESEngine;
import org.bc.crypto.engines.RC2Engine;
import org.bc.crypto.engines.TwofishEngine;
import org.bc.crypto.modes.AEADBlockCipher;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.crypto.modes.CCMBlockCipher;
import org.bc.crypto.modes.CFBBlockCipher;
import org.bc.crypto.modes.CTSBlockCipher;
import org.bc.crypto.modes.EAXBlockCipher;
import org.bc.crypto.modes.GCMBlockCipher;
import org.bc.crypto.modes.GOFBBlockCipher;
import org.bc.crypto.modes.OFBBlockCipher;
import org.bc.crypto.modes.OpenPGPCFBBlockCipher;
import org.bc.crypto.modes.PGPCFBBlockCipher;
import org.bc.crypto.modes.SICBlockCipher;
import org.bc.crypto.paddings.BlockCipherPadding;
import org.bc.crypto.paddings.ISO10126d2Padding;
import org.bc.crypto.paddings.ISO7816d4Padding;
import org.bc.crypto.paddings.PaddedBufferedBlockCipher;
import org.bc.crypto.paddings.TBCPadding;
import org.bc.crypto.paddings.X923Padding;
import org.bc.crypto.paddings.ZeroBytePadding;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.params.ParametersWithSBox;
import org.bc.crypto.params.RC2Parameters;
import org.bc.crypto.params.RC5Parameters;
import org.bc.jcajce.provider.symmetric.util.BCPBEKey;
import org.bc.jcajce.provider.symmetric.util.PBE;
import org.bc.jce.spec.GOST28147ParameterSpec;
import org.bc.jce.spec.RepeatedSecretKeySpec;
import org.bc.util.Strings;

public class JCEBlockCipher extends CipherSpi implements PBE {
   private Class[] availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class, GOST28147ParameterSpec.class};
   private BlockCipher baseEngine;
   private JCEBlockCipher.GenericBlockCipher cipher;
   private ParametersWithIV ivParam;
   private int ivLength = 0;
   private boolean padded;
   private PBEParameterSpec pbeSpec = null;
   private String pbeAlgorithm = null;
   private String modeName = null;
   private AlgorithmParameters engineParams;

   protected JCEBlockCipher(BlockCipher var1) {
      this.baseEngine = var1;
      this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(var1);
   }

   protected JCEBlockCipher(BlockCipher var1, int var2) {
      this.baseEngine = var1;
      this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(var1);
      this.ivLength = var2 / 8;
   }

   protected JCEBlockCipher(BufferedBlockCipher var1, int var2) {
      this.baseEngine = var1.getUnderlyingCipher();
      this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(var1);
      this.ivLength = var2 / 8;
   }

   protected int engineGetBlockSize() {
      return this.baseEngine.getBlockSize();
   }

   protected byte[] engineGetIV() {
      return this.ivParam != null ? this.ivParam.getIV() : null;
   }

   protected int engineGetKeySize(Key var1) {
      return var1.getEncoded().length * 8;
   }

   protected int engineGetOutputSize(int var1) {
      return this.cipher.getOutputSize(var1);
   }

   protected AlgorithmParameters engineGetParameters() {
      if (this.engineParams == null) {
         if (this.pbeSpec != null) {
            try {
               this.engineParams = AlgorithmParameters.getInstance(this.pbeAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
               this.engineParams.init(this.pbeSpec);
            } catch (Exception var4) {
               return null;
            }
         } else if (this.ivParam != null) {
            String var1 = this.cipher.getUnderlyingCipher().getAlgorithmName();
            if (var1.indexOf(47) >= 0) {
               var1 = var1.substring(0, var1.indexOf(47));
            }

            try {
               this.engineParams = AlgorithmParameters.getInstance(var1, BouncyCastleProvider.PROVIDER_NAME);
               this.engineParams.init(this.ivParam.getIV());
            } catch (Exception var3) {
               throw new RuntimeException(var3.toString());
            }
         }
      }

      return this.engineParams;
   }

   protected void engineSetMode(String var1) throws NoSuchAlgorithmException {
      this.modeName = Strings.toUpperCase(var1);
      if (this.modeName.equals("ECB")) {
         this.ivLength = 0;
         this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.baseEngine);
      } else if (this.modeName.equals("CBC")) {
         this.ivLength = this.baseEngine.getBlockSize();
         this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new CBCBlockCipher(this.baseEngine));
      } else {
         int var2;
         if (this.modeName.startsWith("OFB")) {
            this.ivLength = this.baseEngine.getBlockSize();
            if (this.modeName.length() != 3) {
               var2 = Integer.parseInt(this.modeName.substring(3));
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new OFBBlockCipher(this.baseEngine, var2));
            } else {
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new OFBBlockCipher(this.baseEngine, 8 * this.baseEngine.getBlockSize()));
            }
         } else if (this.modeName.startsWith("CFB")) {
            this.ivLength = this.baseEngine.getBlockSize();
            if (this.modeName.length() != 3) {
               var2 = Integer.parseInt(this.modeName.substring(3));
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new CFBBlockCipher(this.baseEngine, var2));
            } else {
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new CFBBlockCipher(this.baseEngine, 8 * this.baseEngine.getBlockSize()));
            }
         } else if (this.modeName.startsWith("PGP")) {
            boolean var3 = this.modeName.equalsIgnoreCase("PGPCFBwithIV");
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new PGPCFBBlockCipher(this.baseEngine, var3));
         } else if (this.modeName.equalsIgnoreCase("OpenPGPCFB")) {
            this.ivLength = 0;
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new OpenPGPCFBBlockCipher(this.baseEngine));
         } else if (this.modeName.startsWith("SIC")) {
            this.ivLength = this.baseEngine.getBlockSize();
            if (this.ivLength < 16) {
               throw new IllegalArgumentException("Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
            }

            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(this.baseEngine)));
         } else if (this.modeName.startsWith("CTR")) {
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new SICBlockCipher(this.baseEngine)));
         } else if (this.modeName.startsWith("GOFB")) {
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(new GOFBBlockCipher(this.baseEngine)));
         } else if (this.modeName.startsWith("CTS")) {
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new CTSBlockCipher(new CBCBlockCipher(this.baseEngine)));
         } else if (this.modeName.startsWith("CCM")) {
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.AEADGenericBlockCipher(new CCMBlockCipher(this.baseEngine));
         } else if (this.modeName.startsWith("EAX")) {
            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.AEADGenericBlockCipher(new EAXBlockCipher(this.baseEngine));
         } else {
            if (!this.modeName.startsWith("GCM")) {
               throw new NoSuchAlgorithmException("can't support mode " + var1);
            }

            this.ivLength = this.baseEngine.getBlockSize();
            this.cipher = new JCEBlockCipher.AEADGenericBlockCipher(new GCMBlockCipher(this.baseEngine));
         }
      }

   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      String var2 = Strings.toUpperCase(var1);
      if (var2.equals("NOPADDING")) {
         if (this.cipher.wrapOnNoPadding()) {
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new BufferedBlockCipher(this.cipher.getUnderlyingCipher()));
         }
      } else if (var2.equals("WITHCTS")) {
         this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(new CTSBlockCipher(this.cipher.getUnderlyingCipher()));
      } else {
         this.padded = true;
         if (this.isAEADModeName(this.modeName)) {
            throw new NoSuchPaddingException("Only NoPadding can be used with AEAD modes.");
         }

         if (!var2.equals("PKCS5PADDING") && !var2.equals("PKCS7PADDING")) {
            if (var2.equals("ZEROBYTEPADDING")) {
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ZeroBytePadding());
            } else if (!var2.equals("ISO10126PADDING") && !var2.equals("ISO10126-2PADDING")) {
               if (!var2.equals("X9.23PADDING") && !var2.equals("X923PADDING")) {
                  if (!var2.equals("ISO7816-4PADDING") && !var2.equals("ISO9797-1PADDING")) {
                     if (!var2.equals("TBCPADDING")) {
                        throw new NoSuchPaddingException("Padding " + var1 + " unknown.");
                     }

                     this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new TBCPadding());
                  } else {
                     this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ISO7816d4Padding());
                  }
               } else {
                  this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new X923Padding());
               }
            } else {
               this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher(), new ISO10126d2Padding());
            }
         } else {
            this.cipher = new JCEBlockCipher.BufferedGenericBlockCipher(this.cipher.getUnderlyingCipher());
         }
      }

   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.pbeSpec = null;
      this.pbeAlgorithm = null;
      this.engineParams = null;
      if (!(var2 instanceof SecretKey)) {
         throw new InvalidKeyException("Key for algorithm " + var2.getAlgorithm() + " not suitable for symmetric enryption.");
      } else if (var3 == null && this.baseEngine.getAlgorithmName().startsWith("RC5-64")) {
         throw new InvalidAlgorithmParameterException("RC5 requires an RC5ParametersSpec to be passed in.");
      } else {
         Object var5;
         if (var2 instanceof BCPBEKey) {
            BCPBEKey var6 = (BCPBEKey)var2;
            if (var6.getOID() != null) {
               this.pbeAlgorithm = var6.getOID().getId();
            } else {
               this.pbeAlgorithm = var6.getAlgorithm();
            }

            if (var6.getParam() != null) {
               var5 = var6.getParam();
               this.pbeSpec = new PBEParameterSpec(var6.getSalt(), var6.getIterationCount());
            } else {
               if (!(var3 instanceof PBEParameterSpec)) {
                  throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
               }

               this.pbeSpec = (PBEParameterSpec)var3;
               var5 = PBE.Util.makePBEParameters(var6, var3, this.cipher.getUnderlyingCipher().getAlgorithmName());
            }

            if (var5 instanceof ParametersWithIV) {
               this.ivParam = (ParametersWithIV)var5;
            }
         } else if (var3 == null) {
            var5 = new KeyParameter(var2.getEncoded());
         } else if (var3 instanceof IvParameterSpec) {
            if (this.ivLength != 0) {
               IvParameterSpec var9 = (IvParameterSpec)var3;
               if (var9.getIV().length != this.ivLength && !this.isAEADModeName(this.modeName)) {
                  throw new InvalidAlgorithmParameterException("IV must be " + this.ivLength + " bytes long.");
               }

               if (var2 instanceof RepeatedSecretKeySpec) {
                  var5 = new ParametersWithIV((CipherParameters)null, var9.getIV());
                  this.ivParam = (ParametersWithIV)var5;
               } else {
                  var5 = new ParametersWithIV(new KeyParameter(var2.getEncoded()), var9.getIV());
                  this.ivParam = (ParametersWithIV)var5;
               }
            } else {
               if (this.modeName != null && this.modeName.equals("ECB")) {
                  throw new InvalidAlgorithmParameterException("ECB mode does not use an IV");
               }

               var5 = new KeyParameter(var2.getEncoded());
            }
         } else if (var3 instanceof GOST28147ParameterSpec) {
            GOST28147ParameterSpec var10 = (GOST28147ParameterSpec)var3;
            var5 = new ParametersWithSBox(new KeyParameter(var2.getEncoded()), ((GOST28147ParameterSpec)var3).getSbox());
            if (var10.getIV() != null && this.ivLength != 0) {
               var5 = new ParametersWithIV((CipherParameters)var5, var10.getIV());
               this.ivParam = (ParametersWithIV)var5;
            }
         } else if (var3 instanceof RC2ParameterSpec) {
            RC2ParameterSpec var11 = (RC2ParameterSpec)var3;
            var5 = new RC2Parameters(var2.getEncoded(), ((RC2ParameterSpec)var3).getEffectiveKeyBits());
            if (var11.getIV() != null && this.ivLength != 0) {
               var5 = new ParametersWithIV((CipherParameters)var5, var11.getIV());
               this.ivParam = (ParametersWithIV)var5;
            }
         } else {
            if (!(var3 instanceof RC5ParameterSpec)) {
               throw new InvalidAlgorithmParameterException("unknown parameter type.");
            }

            RC5ParameterSpec var12 = (RC5ParameterSpec)var3;
            var5 = new RC5Parameters(var2.getEncoded(), ((RC5ParameterSpec)var3).getRounds());
            if (!this.baseEngine.getAlgorithmName().startsWith("RC5")) {
               throw new InvalidAlgorithmParameterException("RC5 parameters passed to a cipher that is not RC5.");
            }

            if (this.baseEngine.getAlgorithmName().equals("RC5-32")) {
               if (var12.getWordSize() != 32) {
                  throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 32 not " + var12.getWordSize() + ".");
               }
            } else if (this.baseEngine.getAlgorithmName().equals("RC5-64") && var12.getWordSize() != 64) {
               throw new InvalidAlgorithmParameterException("RC5 already set up for a word size of 64 not " + var12.getWordSize() + ".");
            }

            if (var12.getIV() != null && this.ivLength != 0) {
               var5 = new ParametersWithIV((CipherParameters)var5, var12.getIV());
               this.ivParam = (ParametersWithIV)var5;
            }
         }

         if (this.ivLength != 0 && !(var5 instanceof ParametersWithIV)) {
            SecureRandom var13 = var4;
            if (var4 == null) {
               var13 = new SecureRandom();
            }

            if (var1 != 1 && var1 != 3) {
               if (this.cipher.getUnderlyingCipher().getAlgorithmName().indexOf("PGPCFB") < 0) {
                  throw new InvalidAlgorithmParameterException("no IV set when one expected");
               }
            } else {
               byte[] var7 = new byte[this.ivLength];
               var13.nextBytes(var7);
               var5 = new ParametersWithIV((CipherParameters)var5, var7);
               this.ivParam = (ParametersWithIV)var5;
            }
         }

         if (var4 != null && this.padded) {
            var5 = new ParametersWithRandom((CipherParameters)var5, var4);
         }

         try {
            switch(var1) {
            case 1:
            case 3:
               this.cipher.init(true, (CipherParameters)var5);
               break;
            case 2:
            case 4:
               this.cipher.init(false, (CipherParameters)var5);
               break;
            default:
               throw new InvalidParameterException("unknown opmode " + var1 + " passed");
            }

         } catch (Exception var8) {
            throw new InvalidKeyException(var8.getMessage());
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

      this.engineInit(var1, var2, var5, var4);
      this.engineParams = var3;
   }

   protected void engineInit(int var1, Key var2, SecureRandom var3) throws InvalidKeyException {
      try {
         this.engineInit(var1, var2, (AlgorithmParameterSpec)null, var3);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new InvalidKeyException(var5.getMessage());
      }
   }

   protected byte[] engineUpdate(byte[] var1, int var2, int var3) {
      int var4 = this.cipher.getUpdateOutputSize(var3);
      if (var4 > 0) {
         byte[] var5 = new byte[var4];
         int var6 = this.cipher.processBytes(var1, var2, var3, var5, 0);
         if (var6 == 0) {
            return null;
         } else if (var6 != var5.length) {
            byte[] var7 = new byte[var6];
            System.arraycopy(var5, 0, var7, 0, var6);
            return var7;
         } else {
            return var5;
         }
      } else {
         this.cipher.processBytes(var1, var2, var3, (byte[])null, 0);
         return null;
      }
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      try {
         return this.cipher.processBytes(var1, var2, var3, var4, var5);
      } catch (DataLengthException var7) {
         throw new ShortBufferException(var7.getMessage());
      }
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) throws IllegalBlockSizeException, BadPaddingException {
      int var4 = 0;
      byte[] var5 = new byte[this.engineGetOutputSize(var3)];
      if (var3 != 0) {
         var4 = this.cipher.processBytes(var1, var2, var3, var5, 0);
      }

      try {
         var4 += this.cipher.doFinal(var5, var4);
      } catch (DataLengthException var7) {
         throw new IllegalBlockSizeException(var7.getMessage());
      } catch (InvalidCipherTextException var8) {
         throw new BadPaddingException(var8.getMessage());
      }

      if (var4 == var5.length) {
         return var5;
      } else {
         byte[] var6 = new byte[var4];
         System.arraycopy(var5, 0, var6, 0, var4);
         return var6;
      }
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
      try {
         int var6 = 0;
         if (var3 != 0) {
            var6 = this.cipher.processBytes(var1, var2, var3, var4, var5);
         }

         return var6 + this.cipher.doFinal(var4, var5 + var6);
      } catch (OutputLengthException var7) {
         throw new ShortBufferException(var7.getMessage());
      } catch (DataLengthException var8) {
         throw new IllegalBlockSizeException(var8.getMessage());
      } catch (InvalidCipherTextException var9) {
         throw new BadPaddingException(var9.getMessage());
      }
   }

   private boolean isAEADModeName(String var1) {
      return "CCM".equals(var1) || "EAX".equals(var1) || "GCM".equals(var1);
   }

   protected byte[] engineWrap(Key var1) throws IllegalBlockSizeException, InvalidKeyException {
      byte[] var2 = var1.getEncoded();
      if (var2 == null) {
         throw new InvalidKeyException("Cannot wrap key, null encoding.");
      } else {
         try {
            return this.engineDoFinal(var2, 0, var2.length);
         } catch (BadPaddingException var4) {
            throw new IllegalBlockSizeException(var4.getMessage());
         }
      }
   }

   protected Key engineUnwrap(byte[] var1, String var2, int var3) throws InvalidKeyException {
      byte[] var4;
      try {
         var4 = this.engineDoFinal(var1, 0, var1.length);
      } catch (BadPaddingException var8) {
         throw new InvalidKeyException(var8.getMessage());
      } catch (IllegalBlockSizeException var9) {
         throw new InvalidKeyException(var9.getMessage());
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
         } catch (NoSuchProviderException var10) {
            throw new InvalidKeyException("Unknown key type " + var10.getMessage());
         } catch (NoSuchAlgorithmException var11) {
            throw new InvalidKeyException("Unknown key type " + var11.getMessage());
         } catch (InvalidKeySpecException var12) {
            throw new InvalidKeyException("Unknown key type " + var12.getMessage());
         }

         throw new InvalidKeyException("Unknown key type " + var3);
      }
   }

   private static class AEADGenericBlockCipher implements JCEBlockCipher.GenericBlockCipher {
      private AEADBlockCipher cipher;

      AEADGenericBlockCipher(AEADBlockCipher var1) {
         this.cipher = var1;
      }

      public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
         this.cipher.init(var1, var2);
      }

      public String getAlgorithmName() {
         return this.cipher.getUnderlyingCipher().getAlgorithmName();
      }

      public boolean wrapOnNoPadding() {
         return false;
      }

      public BlockCipher getUnderlyingCipher() {
         return this.cipher.getUnderlyingCipher();
      }

      public int getOutputSize(int var1) {
         return this.cipher.getOutputSize(var1);
      }

      public int getUpdateOutputSize(int var1) {
         return this.cipher.getUpdateOutputSize(var1);
      }

      public int processByte(byte var1, byte[] var2, int var3) throws DataLengthException {
         return this.cipher.processByte(var1, var2, var3);
      }

      public int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException {
         return this.cipher.processBytes(var1, var2, var3, var4, var5);
      }

      public int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException {
         return this.cipher.doFinal(var1, var2);
      }
   }

   private static class BufferedGenericBlockCipher implements JCEBlockCipher.GenericBlockCipher {
      private BufferedBlockCipher cipher;

      BufferedGenericBlockCipher(BufferedBlockCipher var1) {
         this.cipher = var1;
      }

      BufferedGenericBlockCipher(BlockCipher var1) {
         this.cipher = new PaddedBufferedBlockCipher(var1);
      }

      BufferedGenericBlockCipher(BlockCipher var1, BlockCipherPadding var2) {
         this.cipher = new PaddedBufferedBlockCipher(var1, var2);
      }

      public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
         this.cipher.init(var1, var2);
      }

      public boolean wrapOnNoPadding() {
         return !(this.cipher instanceof CTSBlockCipher);
      }

      public String getAlgorithmName() {
         return this.cipher.getUnderlyingCipher().getAlgorithmName();
      }

      public BlockCipher getUnderlyingCipher() {
         return this.cipher.getUnderlyingCipher();
      }

      public int getOutputSize(int var1) {
         return this.cipher.getOutputSize(var1);
      }

      public int getUpdateOutputSize(int var1) {
         return this.cipher.getUpdateOutputSize(var1);
      }

      public int processByte(byte var1, byte[] var2, int var3) throws DataLengthException {
         return this.cipher.processByte(var1, var2, var3);
      }

      public int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException {
         return this.cipher.processBytes(var1, var2, var3, var4, var5);
      }

      public int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException {
         return this.cipher.doFinal(var1, var2);
      }
   }

   private interface GenericBlockCipher {
      void init(boolean var1, CipherParameters var2) throws IllegalArgumentException;

      boolean wrapOnNoPadding();

      String getAlgorithmName();

      BlockCipher getUnderlyingCipher();

      int getOutputSize(int var1);

      int getUpdateOutputSize(int var1);

      int processByte(byte var1, byte[] var2, int var3) throws DataLengthException;

      int processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) throws DataLengthException;

      int doFinal(byte[] var1, int var2) throws IllegalStateException, InvalidCipherTextException;
   }

   public static class PBEWithAESCBC extends JCEBlockCipher {
      public PBEWithAESCBC() {
         super(new CBCBlockCipher(new AESFastEngine()));
      }
   }

   public static class PBEWithMD5AndDES extends JCEBlockCipher {
      public PBEWithMD5AndDES() {
         super(new CBCBlockCipher(new DESEngine()));
      }
   }

   public static class PBEWithMD5AndRC2 extends JCEBlockCipher {
      public PBEWithMD5AndRC2() {
         super(new CBCBlockCipher(new RC2Engine()));
      }
   }

   public static class PBEWithSHA1AndDES extends JCEBlockCipher {
      public PBEWithSHA1AndDES() {
         super(new CBCBlockCipher(new DESEngine()));
      }
   }

   public static class PBEWithSHA1AndRC2 extends JCEBlockCipher {
      public PBEWithSHA1AndRC2() {
         super(new CBCBlockCipher(new RC2Engine()));
      }
   }

   public static class PBEWithSHAAnd128BitRC2 extends JCEBlockCipher {
      public PBEWithSHAAnd128BitRC2() {
         super(new CBCBlockCipher(new RC2Engine()));
      }
   }

   public static class PBEWithSHAAnd40BitRC2 extends JCEBlockCipher {
      public PBEWithSHAAnd40BitRC2() {
         super(new CBCBlockCipher(new RC2Engine()));
      }
   }

   public static class PBEWithSHAAndTwofish extends JCEBlockCipher {
      public PBEWithSHAAndTwofish() {
         super(new CBCBlockCipher(new TwofishEngine()));
      }
   }
}
