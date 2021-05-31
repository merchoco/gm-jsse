package cn.gmssl.security.ec;

import cn.gmssl.security.util.DerValue;
import cn.gmssl.security.util.ObjectIdentifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import java.util.Iterator;

public final class ECParameters extends AlgorithmParametersSpi {
   private ECParameterSpec paramSpec;

   public static ECPoint decodePoint(byte[] var0, EllipticCurve var1) throws IOException {
      if (var0.length != 0 && var0[0] == 4) {
         int var2 = var1.getField().getFieldSize() + 7 >> 3;
         if (var0.length != var2 * 2 + 1) {
            throw new IOException("Point does not match field size");
         } else {
            byte[] var3 = new byte[var2];
            byte[] var4 = new byte[var2];
            System.arraycopy(var0, 1, var3, 0, var2);
            System.arraycopy(var0, var2 + 1, var4, 0, var2);
            return new ECPoint(new BigInteger(1, var3), new BigInteger(1, var4));
         }
      } else {
         throw new IOException("Only uncompressed point format supported");
      }
   }

   public static byte[] encodePoint(ECPoint var0, EllipticCurve var1) {
      int var2 = var1.getField().getFieldSize() + 7 >> 3;
      byte[] var3 = trimZeroes(var0.getAffineX().toByteArray());
      byte[] var4 = trimZeroes(var0.getAffineY().toByteArray());
      if (var3.length <= var2 && var4.length <= var2) {
         byte[] var5 = new byte[1 + (var2 << 1)];
         var5[0] = 4;
         System.arraycopy(var3, 0, var5, var2 - var3.length + 1, var3.length);
         System.arraycopy(var4, 0, var5, var5.length - var4.length, var4.length);
         return var5;
      } else {
         throw new RuntimeException("Point coordinates do not match field size");
      }
   }

   static byte[] trimZeroes(byte[] var0) {
      int var1;
      for(var1 = 0; var1 < var0.length - 1 && var0[var1] == 0; ++var1) {
         ;
      }

      if (var1 == 0) {
         return var0;
      } else {
         byte[] var2 = new byte[var0.length - var1];
         System.arraycopy(var0, var1, var2, 0, var2.length);
         return var2;
      }
   }

   public static NamedCurve getNamedCurve(ECParameterSpec var0) {
      if (!(var0 instanceof NamedCurve) && var0 != null) {
         int var1 = var0.getCurve().getField().getFieldSize();
         Iterator var3 = NamedCurve.knownECParameterSpecs().iterator();

         ECParameterSpec var2;
         do {
            if (!var3.hasNext()) {
               return null;
            }

            var2 = (ECParameterSpec)var3.next();
         } while(var2.getCurve().getField().getFieldSize() != var1 || !var2.getCurve().equals(var0.getCurve()) || !var2.getGenerator().equals(var0.getGenerator()) || !var2.getOrder().equals(var0.getOrder()) || var2.getCofactor() != var0.getCofactor());

         return (NamedCurve)var2;
      } else {
         return (NamedCurve)var0;
      }
   }

   public static String getCurveName(ECParameterSpec var0) {
      NamedCurve var1 = getNamedCurve(var0);
      return var1 == null ? null : var1.getObjectIdentifier().toString();
   }

   public static byte[] encodeParameters(ECParameterSpec var0) {
      NamedCurve var1 = getNamedCurve(var0);
      if (var1 == null) {
         throw new RuntimeException("Not a known named curve: " + var0);
      } else {
         return var1.getEncoded();
      }
   }

   public static ECParameterSpec decodeParameters(byte[] var0) throws IOException {
      DerValue var1 = new DerValue(var0);
      if (var1.tag == 6) {
         ObjectIdentifier var2 = var1.getOID();
         ECParameterSpec var3 = NamedCurve.getECParameterSpec(var2);
         if (var3 == null) {
            throw new IOException("Unknown named curve: " + var2);
         } else {
            return var3;
         }
      } else {
         throw new IOException("Only named ECParameters supported");
      }
   }

   static AlgorithmParameters getAlgorithmParameters(ECParameterSpec var0) throws InvalidKeyException {
      try {
         AlgorithmParameters var1 = AlgorithmParameters.getInstance("EC", ECKeyFactory.ecInternalProvider);
         var1.init(var0);
         return var1;
      } catch (GeneralSecurityException var2) {
         throw new InvalidKeyException("EC parameters error", var2);
      }
   }

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (var1 instanceof ECParameterSpec) {
         this.paramSpec = getNamedCurve((ECParameterSpec)var1);
         if (this.paramSpec == null) {
            throw new InvalidParameterSpecException("Not a supported named curve: " + var1);
         }
      } else {
         if (!(var1 instanceof ECGenParameterSpec)) {
            if (var1 == null) {
               throw new InvalidParameterSpecException("paramSpec must not be null");
            }

            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
         }

         String var2 = ((ECGenParameterSpec)var1).getName();
         ECParameterSpec var3 = NamedCurve.getECParameterSpec(var2);
         if (var3 == null) {
            throw new InvalidParameterSpecException("Unknown curve: " + var2);
         }

         this.paramSpec = var3;
      }

   }

   protected void engineInit(byte[] var1) throws IOException {
      this.paramSpec = decodeParameters(var1);
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      this.engineInit(var1);
   }

   protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> var1) throws InvalidParameterSpecException {
      if (var1.isAssignableFrom(ECParameterSpec.class)) {
         return (T) this.paramSpec;
      } else if (var1.isAssignableFrom(ECGenParameterSpec.class)) {
         return (T) new ECGenParameterSpec(getCurveName(this.paramSpec));
      } else {
         throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
      }
   }

   protected byte[] engineGetEncoded() throws IOException {
      return encodeParameters(this.paramSpec);
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      return this.engineGetEncoded();
   }

   protected String engineToString() {
      return this.paramSpec.toString();
   }
}
