package org.bc.jcajce.provider.symmetric.util;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.PBEParametersGenerator;
import org.bc.crypto.digests.GOST3411Digest;
import org.bc.crypto.digests.MD2Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.TigerDigest;
import org.bc.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bc.crypto.generators.PKCS12ParametersGenerator;
import org.bc.crypto.generators.PKCS5S1ParametersGenerator;
import org.bc.crypto.generators.PKCS5S2ParametersGenerator;
import org.bc.crypto.params.DESParameters;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;

public interface PBE {
   int MD5 = 0;
   int SHA1 = 1;
   int RIPEMD160 = 2;
   int TIGER = 3;
   int SHA256 = 4;
   int MD2 = 5;
   int GOST3411 = 6;
   int PKCS5S1 = 0;
   int PKCS5S2 = 1;
   int PKCS12 = 2;
   int OPENSSL = 3;

   public static class Util {
      private static PBEParametersGenerator makePBEGenerator(int var0, int var1) {
         Object var2;
         if (var0 == 0) {
            switch(var1) {
            case 0:
               var2 = new PKCS5S1ParametersGenerator(new MD5Digest());
               break;
            case 1:
               var2 = new PKCS5S1ParametersGenerator(new SHA1Digest());
               break;
            case 2:
            case 3:
            case 4:
            default:
               throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
            case 5:
               var2 = new PKCS5S1ParametersGenerator(new MD2Digest());
            }
         } else if (var0 == 1) {
            var2 = new PKCS5S2ParametersGenerator();
         } else if (var0 == 2) {
            switch(var1) {
            case 0:
               var2 = new PKCS12ParametersGenerator(new MD5Digest());
               break;
            case 1:
               var2 = new PKCS12ParametersGenerator(new SHA1Digest());
               break;
            case 2:
               var2 = new PKCS12ParametersGenerator(new RIPEMD160Digest());
               break;
            case 3:
               var2 = new PKCS12ParametersGenerator(new TigerDigest());
               break;
            case 4:
               var2 = new PKCS12ParametersGenerator(new SHA256Digest());
               break;
            case 5:
               var2 = new PKCS12ParametersGenerator(new MD2Digest());
               break;
            case 6:
               var2 = new PKCS12ParametersGenerator(new GOST3411Digest());
               break;
            default:
               throw new IllegalStateException("unknown digest scheme for PBE encryption.");
            }
         } else {
            var2 = new OpenSSLPBEParametersGenerator();
         }

         return (PBEParametersGenerator)var2;
      }

      public static CipherParameters makePBEParameters(BCPBEKey var0, AlgorithmParameterSpec var1, String var2) {
         if (var1 != null && var1 instanceof PBEParameterSpec) {
            PBEParameterSpec var3 = (PBEParameterSpec)var1;
            PBEParametersGenerator var4 = makePBEGenerator(var0.getType(), var0.getDigest());
            byte[] var5 = var0.getEncoded();
            if (var0.shouldTryWrongPKCS12()) {
               var5 = new byte[2];
            }

            var4.init(var5, var3.getSalt(), var3.getIterationCount());
            CipherParameters var6;
            if (var0.getIvSize() != 0) {
               var6 = var4.generateDerivedParameters(var0.getKeySize(), var0.getIvSize());
            } else {
               var6 = var4.generateDerivedParameters(var0.getKeySize());
            }

            if (var2.startsWith("DES")) {
               KeyParameter var7;
               if (var6 instanceof ParametersWithIV) {
                  var7 = (KeyParameter)((ParametersWithIV)var6).getParameters();
                  DESParameters.setOddParity(var7.getKey());
               } else {
                  var7 = (KeyParameter)var6;
                  DESParameters.setOddParity(var7.getKey());
               }
            }

            for(int var8 = 0; var8 != var5.length; ++var8) {
               var5[var8] = 0;
            }

            return var6;
         } else {
            throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
         }
      }

      public static CipherParameters makePBEMacParameters(BCPBEKey var0, AlgorithmParameterSpec var1) {
         if (var1 != null && var1 instanceof PBEParameterSpec) {
            PBEParameterSpec var2 = (PBEParameterSpec)var1;
            PBEParametersGenerator var3 = makePBEGenerator(var0.getType(), var0.getDigest());
            byte[] var4 = var0.getEncoded();
            if (var0.shouldTryWrongPKCS12()) {
               var4 = new byte[2];
            }

            var3.init(var4, var2.getSalt(), var2.getIterationCount());
            CipherParameters var5 = var3.generateDerivedMacParameters(var0.getKeySize());

            for(int var6 = 0; var6 != var4.length; ++var6) {
               var4[var6] = 0;
            }

            return var5;
         } else {
            throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
         }
      }

      public static CipherParameters makePBEParameters(PBEKeySpec var0, int var1, int var2, int var3, int var4) {
         PBEParametersGenerator var5 = makePBEGenerator(var1, var2);
         byte[] var6;
         if (var1 == 2) {
            var6 = PBEParametersGenerator.PKCS12PasswordToBytes(var0.getPassword());
         } else {
            var6 = PBEParametersGenerator.PKCS5PasswordToBytes(var0.getPassword());
         }

         var5.init(var6, var0.getSalt(), var0.getIterationCount());
         CipherParameters var7;
         if (var4 != 0) {
            var7 = var5.generateDerivedParameters(var3, var4);
         } else {
            var7 = var5.generateDerivedParameters(var3);
         }

         for(int var8 = 0; var8 != var6.length; ++var8) {
            var6[var8] = 0;
         }

         return var7;
      }

      public static CipherParameters makePBEMacParameters(PBEKeySpec var0, int var1, int var2, int var3) {
         PBEParametersGenerator var4 = makePBEGenerator(var1, var2);
         byte[] var5;
         if (var1 == 2) {
            var5 = PBEParametersGenerator.PKCS12PasswordToBytes(var0.getPassword());
         } else {
            var5 = PBEParametersGenerator.PKCS5PasswordToBytes(var0.getPassword());
         }

         var4.init(var5, var0.getSalt(), var0.getIterationCount());
         CipherParameters var6 = var4.generateDerivedMacParameters(var3);

         for(int var7 = 0; var7 != var5.length; ++var7) {
            var5[var7] = 0;
         }

         return var6;
      }
   }
}
