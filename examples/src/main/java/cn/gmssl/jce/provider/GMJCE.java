package cn.gmssl.jce.provider;

import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import org.bc.jce.provider.BouncyCastleProvider;

public class GMJCE extends Provider {
   private static final long serialVersionUID = 1443132961964116159L;
   private static final String INFO = "GM JCE provider";
   public static final String NAME = "GMJCE";

   static {
      Security.addProvider(new BouncyCastleProvider());
   }

   public GMJCE() {
      super("GMJCE", 1.0D, "GM JCE provider");

      try {
         Class var1 = Class.forName("cn.gmssl.jce.provider.GMFree");
         Method var2 = var1.getMethod("init");
         var2.invoke((Object)null);
      } catch (Throwable var3) {
         ;
      }

      this.put("Cipher.SM4", "cn.gmssl.crypto.SM4JCE$ECB");
      this.put("Cipher.SM4/CBC", "cn.gmssl.crypto.SM4JCE$CBC");
      this.put("Cipher.SM2", "cn.gmssl.crypto.SM2DerJce");
      this.put("MessageDigest.SM3", "cn.gmssl.crypto.SM3Jce");
      this.put("Mac.HmacSM3", "cn.gmssl.crypto.HMacSM3");
      this.put("KeyAgreement.SM2", "cn.gmssl.crypto.impl.sm2.SM2KeyAgreement");
      this.put("Signature.1.2.156.10197.1.501", "cn.gmssl.crypto.impl.sm2.SM3WithSM2");
      this.put("Signature.SM3WithSM2", "cn.gmssl.crypto.impl.sm2.SM3WithSM2");
      this.put("Signature.NoneWithSM2", "cn.gmssl.crypto.impl.sm2.NoneWithSM2");
      this.put("CertificateFactory.X.509", "org.bc.jcajce.provider.asymmetric.x509.CertificateFactory");
      this.put("Alg.Alias.CertificateFactory.X509", "X.509");
      this.put("KeyFactory.ECDSA", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$ECDSA");
      this.put("KeyFactory.EC", "org.bc.jcajce.provider.asymmetric.ec.KeyFactorySpi$EC");
      this.put("Alg.Alias.KeyFactory.SM2", "EC");
      this.put("Alg.Alias.KeyFactory.1.2.840.10045.2.1", "EC");
      this.put("KeyPairGenerator.SM2", "cn.gmssl.crypto.SM2KeyPairGenerator");
      this.put("KeyPairGenerator.ECDSA", "org.bc.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi$ECDSA");
      this.put("KeyAgreement.SM2", "cn.gmssl.crypto.impl.sm2.SM2KeyAgreement");
      this.put("KeyStore.JKS", "sun.security.provider.JavaKeyStore$JKS");
      this.put("KeyStore.PKCS12", "org.bc.jce.provider.JDKPKCS12KeyStore$BCPKCS12KeyStore");
      this.put("CertPathValidator.PKIX", "org.bc.jce.provider.PKIXCertPathValidatorSpi");
   }
}
