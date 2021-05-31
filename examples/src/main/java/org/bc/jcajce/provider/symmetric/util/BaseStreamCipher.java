package org.bc.jcajce.provider.symmetric.util;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.StreamBlockCipher;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.jce.provider.BouncyCastleProvider;

public class BaseStreamCipher extends BaseWrapCipher implements PBE {
   private Class[] availableSpecs = new Class[]{RC2ParameterSpec.class, RC5ParameterSpec.class, IvParameterSpec.class, PBEParameterSpec.class};
   private StreamCipher cipher;
   private ParametersWithIV ivParam;
   private int ivLength = 0;
   private PBEParameterSpec pbeSpec = null;
   private String pbeAlgorithm = null;

   protected BaseStreamCipher(StreamCipher var1, int var2) {
      this.cipher = var1;
      this.ivLength = var2;
   }

   protected BaseStreamCipher(BlockCipher var1, int var2) {
      this.ivLength = var2;
      this.cipher = new StreamBlockCipher(var1);
   }

   protected int engineGetBlockSize() {
      return 0;
   }

   protected byte[] engineGetIV() {
      return this.ivParam != null ? this.ivParam.getIV() : null;
   }

   protected int engineGetKeySize(Key var1) {
      return var1.getEncoded().length * 8;
   }

   protected int engineGetOutputSize(int var1) {
      return var1;
   }

   protected AlgorithmParameters engineGetParameters() {
      if (this.engineParams == null && this.pbeSpec != null) {
         try {
            AlgorithmParameters var1 = AlgorithmParameters.getInstance(this.pbeAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            var1.init(this.pbeSpec);
            return var1;
         } catch (Exception var2) {
            return null;
         }
      } else {
         return this.engineParams;
      }
   }

   protected void engineSetMode(String var1) {
      if (!var1.equalsIgnoreCase("ECB")) {
         throw new IllegalArgumentException("can't support mode " + var1);
      }
   }

   protected void engineSetPadding(String var1) throws NoSuchPaddingException {
      if (!var1.equalsIgnoreCase("NoPadding")) {
         throw new NoSuchPaddingException("Padding " + var1 + " unknown.");
      }
   }

   protected void engineInit(int var1, Key var2, AlgorithmParameterSpec var3, SecureRandom var4) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.pbeSpec = null;
      this.pbeAlgorithm = null;
      this.engineParams = null;
      if (!(var2 instanceof SecretKey)) {
         throw new InvalidKeyException("Key for algorithm " + var2.getAlgorithm() + " not suitable for symmetric enryption.");
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

               var5 = PBE.Util.makePBEParameters(var6, var3, this.cipher.getAlgorithmName());
               this.pbeSpec = (PBEParameterSpec)var3;
            }

            if (var6.getIvSize() != 0) {
               this.ivParam = (ParametersWithIV)var5;
            }
         } else if (var3 == null) {
            var5 = new KeyParameter(var2.getEncoded());
         } else {
            if (!(var3 instanceof IvParameterSpec)) {
               throw new IllegalArgumentException("unknown parameter type.");
            }

            var5 = new ParametersWithIV(new KeyParameter(var2.getEncoded()), ((IvParameterSpec)var3).getIV());
            this.ivParam = (ParametersWithIV)var5;
         }

         if (this.ivLength != 0 && !(var5 instanceof ParametersWithIV)) {
            SecureRandom var8 = var4;
            if (var4 == null) {
               var8 = new SecureRandom();
            }

            if (var1 != 1 && var1 != 3) {
               throw new InvalidAlgorithmParameterException("no IV set when one expected");
            }

            byte[] var7 = new byte[this.ivLength];
            var8.nextBytes(var7);
            var5 = new ParametersWithIV((CipherParameters)var5, var7);
            this.ivParam = (ParametersWithIV)var5;
         }

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
      byte[] var4 = new byte[var3];
      this.cipher.processBytes(var1, var2, var3, var4, 0);
      return var4;
   }

   protected int engineUpdate(byte[] var1, int var2, int var3, byte[] var4, int var5) throws ShortBufferException {
      try {
         this.cipher.processBytes(var1, var2, var3, var4, var5);
         return var3;
      } catch (DataLengthException var7) {
         throw new ShortBufferException(var7.getMessage());
      }
   }

   protected byte[] engineDoFinal(byte[] var1, int var2, int var3) {
      if (var3 != 0) {
         byte[] var4 = this.engineUpdate(var1, var2, var3);
         this.cipher.reset();
         return var4;
      } else {
         this.cipher.reset();
         return new byte[0];
      }
   }

   protected int engineDoFinal(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      if (var3 != 0) {
         this.cipher.processBytes(var1, var2, var3, var4, var5);
      }

      this.cipher.reset();
      return var3;
   }
}
