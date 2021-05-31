package org.bc.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.Mac;
import org.bc.crypto.digests.MD2Digest;
import org.bc.crypto.digests.MD4Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.RIPEMD128Digest;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.digests.TigerDigest;
import org.bc.crypto.engines.DESEngine;
import org.bc.crypto.engines.RC2Engine;
import org.bc.crypto.macs.CBCBlockCipherMac;
import org.bc.crypto.macs.CFBBlockCipherMac;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.macs.ISO9797Alg3Mac;
import org.bc.crypto.macs.OldHMac;
import org.bc.crypto.paddings.ISO7816d4Padding;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.jcajce.provider.symmetric.util.BCPBEKey;
import org.bc.jcajce.provider.symmetric.util.PBE;

public class JCEMac extends MacSpi implements PBE {
   private Mac macEngine;
   private int pbeType = 2;
   private int pbeHash = 1;
   private int keySize = 160;

   protected JCEMac(Mac var1) {
      this.macEngine = var1;
   }

   protected JCEMac(Mac var1, int var2, int var3, int var4) {
      this.macEngine = var1;
      this.pbeType = var2;
      this.pbeHash = var3;
      this.keySize = var4;
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      if (var1 == null) {
         throw new InvalidKeyException("key is null");
      } else {
         Object var3;
         if (var1 instanceof BCPBEKey) {
            BCPBEKey var4 = (BCPBEKey)var1;
            if (var4.getParam() != null) {
               var3 = var4.getParam();
            } else {
               if (!(var2 instanceof PBEParameterSpec)) {
                  throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
               }

               var3 = PBE.Util.makePBEMacParameters(var4, var2);
            }
         } else if (var2 instanceof IvParameterSpec) {
            var3 = new ParametersWithIV(new KeyParameter(var1.getEncoded()), ((IvParameterSpec)var2).getIV());
         } else {
            if (var2 != null) {
               throw new InvalidAlgorithmParameterException("unknown parameter type.");
            }

            var3 = new KeyParameter(var1.getEncoded());
         }

         this.macEngine.init((CipherParameters)var3);
      }
   }

   protected int engineGetMacLength() {
      return this.macEngine.getMacSize();
   }

   protected void engineReset() {
      this.macEngine.reset();
   }

   protected void engineUpdate(byte var1) {
      this.macEngine.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) {
      this.macEngine.update(var1, var2, var3);
   }

   protected byte[] engineDoFinal() {
      byte[] var1 = new byte[this.engineGetMacLength()];
      this.macEngine.doFinal(var1, 0);
      return var1;
   }

   public static class DES extends JCEMac {
      public DES() {
         super(new CBCBlockCipherMac(new DESEngine()));
      }
   }

   public static class DES64 extends JCEMac {
      public DES64() {
         super(new CBCBlockCipherMac(new DESEngine(), 64));
      }
   }

   public static class DES9797Alg3 extends JCEMac {
      public DES9797Alg3() {
         super(new ISO9797Alg3Mac(new DESEngine()));
      }
   }

   public static class DES9797Alg3with7816d4 extends JCEMac {
      public DES9797Alg3with7816d4() {
         super(new ISO9797Alg3Mac(new DESEngine(), new ISO7816d4Padding()));
      }
   }

   public static class DESCFB8 extends JCEMac {
      public DESCFB8() {
         super(new CFBBlockCipherMac(new DESEngine()));
      }
   }

   public static class MD2 extends JCEMac {
      public MD2() {
         super(new HMac(new MD2Digest()));
      }
   }

   public static class MD4 extends JCEMac {
      public MD4() {
         super(new HMac(new MD4Digest()));
      }
   }

   public static class MD5 extends JCEMac {
      public MD5() {
         super(new HMac(new MD5Digest()));
      }
   }

   public static class OldSHA384 extends JCEMac {
      public OldSHA384() {
         super(new OldHMac(new SHA384Digest()));
      }
   }

   public static class OldSHA512 extends JCEMac {
      public OldSHA512() {
         super(new OldHMac(new SHA512Digest()));
      }
   }

   public static class PBEWithRIPEMD160 extends JCEMac {
      public PBEWithRIPEMD160() {
         super(new HMac(new RIPEMD160Digest()), 2, 2, 160);
      }
   }

   public static class PBEWithSHA extends JCEMac {
      public PBEWithSHA() {
         super(new HMac(new SHA1Digest()), 2, 1, 160);
      }
   }

   public static class PBEWithTiger extends JCEMac {
      public PBEWithTiger() {
         super(new HMac(new TigerDigest()), 2, 3, 192);
      }
   }

   public static class RC2 extends JCEMac {
      public RC2() {
         super(new CBCBlockCipherMac(new RC2Engine()));
      }
   }

   public static class RIPEMD128 extends JCEMac {
      public RIPEMD128() {
         super(new HMac(new RIPEMD128Digest()));
      }
   }

   public static class RIPEMD160 extends JCEMac {
      public RIPEMD160() {
         super(new HMac(new RIPEMD160Digest()));
      }
   }

   public static class SHA1 extends JCEMac {
      public SHA1() {
         super(new HMac(new SHA1Digest()));
      }
   }

   public static class SHA224 extends JCEMac {
      public SHA224() {
         super(new HMac(new SHA224Digest()));
      }
   }

   public static class SHA256 extends JCEMac {
      public SHA256() {
         super(new HMac(new SHA256Digest()));
      }
   }

   public static class SHA384 extends JCEMac {
      public SHA384() {
         super(new HMac(new SHA384Digest()));
      }
   }

   public static class SHA512 extends JCEMac {
      public SHA512() {
         super(new HMac(new SHA512Digest()));
      }
   }

   public static class Tiger extends JCEMac {
      public Tiger() {
         super(new HMac(new TigerDigest()));
      }
   }
}
