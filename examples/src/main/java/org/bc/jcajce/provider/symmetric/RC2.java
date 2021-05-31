package org.bc.jcajce.provider.symmetric;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.RC2CBCParameter;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherKeyGenerator;
import org.bc.crypto.engines.RC2Engine;
import org.bc.crypto.engines.RC2WrapEngine;
import org.bc.crypto.macs.CBCBlockCipherMac;
import org.bc.crypto.macs.CFBBlockCipherMac;
import org.bc.crypto.modes.CBCBlockCipher;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameterGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
import org.bc.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bc.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bc.jcajce.provider.symmetric.util.BaseMac;
import org.bc.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bc.jcajce.provider.util.AlgorithmProvider;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.util.Arrays;

public final class RC2 {
   public static class AlgParamGen extends BaseAlgorithmParameterGenerator {
      RC2ParameterSpec spec = null;

      protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
         if (var1 instanceof RC2ParameterSpec) {
            this.spec = (RC2ParameterSpec)var1;
         } else {
            throw new InvalidAlgorithmParameterException("No supported AlgorithmParameterSpec for RC2 parameter generation.");
         }
      }

      protected AlgorithmParameters engineGenerateParameters() {
         AlgorithmParameters var1;
         if (this.spec == null) {
            byte[] var2 = new byte[8];
            if (this.random == null) {
               this.random = new SecureRandom();
            }

            this.random.nextBytes(var2);

            try {
               var1 = AlgorithmParameters.getInstance("RC2", BouncyCastleProvider.PROVIDER_NAME);
               var1.init(new IvParameterSpec(var2));
            } catch (Exception var5) {
               throw new RuntimeException(var5.getMessage());
            }
         } else {
            try {
               var1 = AlgorithmParameters.getInstance("RC2", BouncyCastleProvider.PROVIDER_NAME);
               var1.init(this.spec);
            } catch (Exception var4) {
               throw new RuntimeException(var4.getMessage());
            }
         }

         return var1;
      }
   }

   public static class AlgParams extends BaseAlgorithmParameters {
      private static final short[] table = new short[]{189, 86, 234, 242, 162, 241, 172, 42, 176, 147, 209, 156, 27, 51, 253, 208, 48, 4, 182, 220, 125, 223, 50, 75, 247, 203, 69, 155, 49, 187, 33, 90, 65, 159, 225, 217, 74, 77, 158, 218, 160, 104, 44, 195, 39, 95, 128, 54, 62, 238, 251, 149, 26, 254, 206, 168, 52, 169, 19, 240, 166, 63, 216, 12, 120, 36, 175, 35, 82, 193, 103, 23, 245, 102, 144, 231, 232, 7, 184, 96, 72, 230, 30, 83, 243, 146, 164, 114, 140, 8, 21, 110, 134, 0, 132, 250, 244, 127, 138, 66, 25, 246, 219, 205, 20, 141, 80, 18, 186, 60, 6, 78, 236, 179, 53, 17, 161, 136, 142, 43, 148, 153, 183, 113, 116, 211, 228, 191, 58, 222, 150, 14, 188, 10, 237, 119, 252, 55, 107, 3, 121, 137, 98, 198, 215, 192, 210, 124, 106, 139, 34, 163, 91, 5, 93, 2, 117, 213, 97, 227, 24, 143, 85, 81, 173, 31, 11, 94, 133, 229, 194, 87, 99, 202, 61, 108, 180, 197, 204, 112, 178, 145, 89, 13, 71, 32, 200, 79, 88, 224, 1, 226, 22, 56, 196, 111, 59, 15, 101, 70, 190, 126, 45, 123, 130, 249, 64, 181, 29, 115, 248, 235, 38, 199, 135, 151, 37, 84, 177, 40, 170, 152, 157, 165, 100, 109, 122, 212, 16, 129, 68, 239, 73, 214, 174, 46, 221, 118, 92, 47, 167, 28, 201, 9, 105, 154, 131, 207, 41, 57, 185, 233, 76, 255, 67, 171};
      private static final short[] ekb = new short[]{93, 190, 155, 139, 17, 153, 110, 77, 89, 243, 133, 166, 63, 183, 131, 197, 228, 115, 107, 58, 104, 90, 192, 71, 160, 100, 52, 12, 241, 208, 82, 165, 185, 30, 150, 67, 65, 216, 212, 44, 219, 248, 7, 119, 42, 202, 235, 239, 16, 28, 22, 13, 56, 114, 47, 137, 193, 249, 128, 196, 109, 174, 48, 61, 206, 32, 99, 254, 230, 26, 199, 184, 80, 232, 36, 23, 252, 37, 111, 187, 106, 163, 68, 83, 217, 162, 1, 171, 188, 182, 31, 152, 238, 154, 167, 45, 79, 158, 142, 172, 224, 198, 73, 70, 41, 244, 148, 138, 175, 225, 91, 195, 179, 123, 87, 209, 124, 156, 237, 135, 64, 140, 226, 203, 147, 20, 201, 97, 46, 229, 204, 246, 94, 168, 92, 214, 117, 141, 98, 149, 88, 105, 118, 161, 74, 181, 85, 9, 120, 51, 130, 215, 221, 121, 245, 27, 11, 222, 38, 33, 40, 116, 4, 151, 86, 223, 60, 240, 55, 57, 220, 255, 6, 164, 234, 66, 8, 218, 180, 113, 176, 207, 18, 122, 78, 250, 108, 29, 132, 0, 200, 127, 145, 69, 170, 43, 194, 177, 143, 213, 186, 242, 173, 25, 178, 103, 54, 247, 15, 10, 146, 125, 227, 157, 233, 144, 62, 35, 39, 102, 19, 236, 129, 21, 189, 34, 191, 159, 126, 169, 81, 75, 76, 251, 2, 211, 112, 134, 49, 231, 59, 5, 3, 84, 96, 72, 101, 24, 210, 205, 95, 50, 136, 14, 53, 253};
      private byte[] iv;
      private int parameterVersion = 58;

      protected byte[] engineGetEncoded() {
         return Arrays.clone(this.iv);
      }

      protected byte[] engineGetEncoded(String var1) throws IOException {
         if (this.isASN1FormatString(var1)) {
            return this.parameterVersion == -1 ? (new RC2CBCParameter(this.engineGetEncoded())).getEncoded() : (new RC2CBCParameter(this.parameterVersion, this.engineGetEncoded())).getEncoded();
         } else {
            return var1.equals("RAW") ? this.engineGetEncoded() : null;
         }
      }

      protected AlgorithmParameterSpec localEngineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
         if (var1 == RC2ParameterSpec.class && this.parameterVersion != -1) {
            return this.parameterVersion < 256 ? new RC2ParameterSpec(ekb[this.parameterVersion], this.iv) : new RC2ParameterSpec(this.parameterVersion, this.iv);
         } else if (var1 == IvParameterSpec.class) {
            return new IvParameterSpec(this.iv);
         } else {
            throw new InvalidParameterSpecException("unknown parameter spec passed to RC2 parameters object.");
         }
      }

      protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
         if (var1 instanceof IvParameterSpec) {
            this.iv = ((IvParameterSpec)var1).getIV();
         } else {
            if (!(var1 instanceof RC2ParameterSpec)) {
               throw new InvalidParameterSpecException("IvParameterSpec or RC2ParameterSpec required to initialise a RC2 parameters algorithm parameters object");
            }

            int var2 = ((RC2ParameterSpec)var1).getEffectiveKeyBits();
            if (var2 != -1) {
               if (var2 < 256) {
                  this.parameterVersion = table[var2];
               } else {
                  this.parameterVersion = var2;
               }
            }

            this.iv = ((RC2ParameterSpec)var1).getIV();
         }

      }

      protected void engineInit(byte[] var1) throws IOException {
         this.iv = Arrays.clone(var1);
      }

      protected void engineInit(byte[] var1, String var2) throws IOException {
         if (this.isASN1FormatString(var2)) {
            RC2CBCParameter var3 = RC2CBCParameter.getInstance(ASN1Primitive.fromByteArray(var1));
            if (var3.getRC2ParameterVersion() != null) {
               this.parameterVersion = var3.getRC2ParameterVersion().intValue();
            }

            this.iv = var3.getIV();
         } else if (var2.equals("RAW")) {
            this.engineInit(var1);
         } else {
            throw new IOException("Unknown parameters format in IV parameters object");
         }
      }

      protected String engineToString() {
         return "RC2 Parameters";
      }
   }

   public static class CBC extends BaseBlockCipher {
      public CBC() {
         super((BlockCipher)(new CBCBlockCipher(new RC2Engine())), 64);
      }
   }

   public static class CBCMAC extends BaseMac {
      public CBCMAC() {
         super(new CBCBlockCipherMac(new RC2Engine()));
      }
   }

   public static class CFB8MAC extends BaseMac {
      public CFB8MAC() {
         super(new CFBBlockCipherMac(new RC2Engine()));
      }
   }

   public static class ECB extends BaseBlockCipher {
      public ECB() {
         super(new RC2Engine());
      }
   }

   public static class KeyGenerator extends BaseKeyGenerator {
      public KeyGenerator() {
         super("RC2", 128, new CipherKeyGenerator());
      }
   }

   public static class Mappings extends AlgorithmProvider {
      private static final String PREFIX = RC2.class.getName();

      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameterGenerator.RC2", PREFIX + "$AlgParamGen");
         var1.addAlgorithm("AlgorithmParameterGenerator.1.2.840.113549.3.2", PREFIX + "$AlgParamGen");
         var1.addAlgorithm("KeyGenerator.RC2", PREFIX + "$KeyGenerator");
         var1.addAlgorithm("KeyGenerator.1.2.840.113549.3.2", PREFIX + "$KeyGenerator");
         var1.addAlgorithm("AlgorithmParameters.RC2", PREFIX + "$AlgParams");
         var1.addAlgorithm("AlgorithmParameters.1.2.840.113549.3.2", PREFIX + "$AlgParams");
         var1.addAlgorithm("Cipher.RC2", PREFIX + "$ECB");
         var1.addAlgorithm("Cipher.RC2WRAP", PREFIX + "$Wrap");
         var1.addAlgorithm("Alg.Alias.Cipher." + PKCSObjectIdentifiers.id_alg_CMSRC2wrap, "RC2WRAP");
         var1.addAlgorithm("Cipher.1.2.840.113549.3.2", PREFIX + "$CBC");
         var1.addAlgorithm("Mac.RC2MAC", PREFIX + "$CBCMAC");
         var1.addAlgorithm("Alg.Alias.Mac.RC2", "RC2MAC");
         var1.addAlgorithm("Mac.RC2MAC/CFB8", PREFIX + "$CFB8MAC");
         var1.addAlgorithm("Alg.Alias.Mac.RC2/CFB8", "RC2MAC/CFB8");
      }
   }

   public static class Wrap extends BaseWrapCipher {
      public Wrap() {
         super(new RC2WrapEngine());
      }
   }
}
