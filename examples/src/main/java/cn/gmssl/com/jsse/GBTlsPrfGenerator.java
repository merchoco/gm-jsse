package cn.gmssl.com.jsse;

import cn.gmssl.sun.security.internal.spec.TlsPrfParameterSpec;
import cn.gmssl.sun.security.ssl.ProtocolVersion;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class GBTlsPrfGenerator extends KeyGeneratorSpi {
   private static final String MSG = "TlsPrfGenerator must be initialized using a TlsPrfParameterSpec";
   private TlsPrfParameterSpec spec;

   protected SecretKey engineGenerateKey() {
      if (this.spec == null) {
         throw new IllegalStateException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
      } else {
         SecretKey var1 = this.spec.getSecret();
         byte[] var2 = var1 == null ? null : var1.getEncoded();

         try {
            byte[] var3 = this.spec.getLabel().getBytes("UTF8");
            int var4 = this.spec.getOutputLength();
            Object var5 = null;
            ProtocolVersion var6 = this.spec.getProtocolVersion();
            byte[] var9;
            if (var6.minor == 0) {
               var9 = TlsUtil.doGBTLS10PRF(var2, var3, this.spec.getSeed(), var4);
            } else {
               var9 = TlsUtil.doGBTLS11PRF(var2, var3, this.spec.getSeed(), var4);
            }

            return new SecretKeySpec(var9, "GBTlsPrf");
         } catch (GeneralSecurityException var7) {
            throw new ProviderException("Could not generate PRF", var7);
         } catch (UnsupportedEncodingException var8) {
            throw new ProviderException("Could not generate PRF", var8);
         }
      }
   }

   protected void engineInit(SecureRandom var1) {
      throw new InvalidParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
   }

   protected void engineInit(AlgorithmParameterSpec var1, SecureRandom var2) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof TlsPrfParameterSpec)) {
         throw new InvalidAlgorithmParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
      } else {
         this.spec = (TlsPrfParameterSpec)var1;
         SecretKey var3 = this.spec.getSecret();
         if (var3 != null && !"RAW".equals(var3.getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
         }
      }
   }

   protected void engineInit(int var1, SecureRandom var2) {
      throw new InvalidParameterException("TlsPrfGenerator must be initialized using a TlsPrfParameterSpec");
   }
}
