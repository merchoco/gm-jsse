package cn.gmssl.sun.security.provider.certpath;

import java.math.BigInteger;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;
import sun.security.util.DisabledAlgorithmConstraints;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509CRLImpl;
import sun.security.x509.X509CertImpl;

public final class AlgorithmChecker extends PKIXCertPathChecker {
   private final AlgorithmConstraints constraints;
   private final PublicKey trustedPubKey;
   private PublicKey prevPubKey;
   private static final Set<CryptoPrimitive> SIGNATURE_PRIMITIVE_SET;
   private static final DisabledAlgorithmConstraints certPathDefaultConstraints;

   static {
      SIGNATURE_PRIMITIVE_SET = EnumSet.of(CryptoPrimitive.SIGNATURE);
      certPathDefaultConstraints = new DisabledAlgorithmConstraints("jdk.certpath.disabledAlgorithms");
   }

   public AlgorithmChecker(TrustAnchor var1) {
      this(var1, certPathDefaultConstraints);
   }

   public AlgorithmChecker(AlgorithmConstraints var1) {
      this.prevPubKey = null;
      this.trustedPubKey = null;
      this.constraints = var1;
   }

   public AlgorithmChecker(TrustAnchor var1, AlgorithmConstraints var2) {
      if (var1 == null) {
         throw new IllegalArgumentException("The trust anchor cannot be null");
      } else {
         if (var1.getTrustedCert() != null) {
            this.trustedPubKey = var1.getTrustedCert().getPublicKey();
         } else {
            this.trustedPubKey = var1.getCAPublicKey();
         }

         this.prevPubKey = this.trustedPubKey;
         this.constraints = var2;
      }
   }

   public void init(boolean var1) throws CertPathValidatorException {
      if (!var1) {
         if (this.trustedPubKey != null) {
            this.prevPubKey = this.trustedPubKey;
         } else {
            this.prevPubKey = null;
         }

      } else {
         throw new CertPathValidatorException("forward checking not supported");
      }
   }

   public boolean isForwardCheckingSupported() {
      return false;
   }

   public Set<String> getSupportedExtensions() {
      return null;
   }

   public void check(Certificate var1, Collection<String> var2) throws CertPathValidatorException {
      if (var1 instanceof X509Certificate && this.constraints != null) {
         Object var3 = (X509Certificate)var1;
         PublicKey var4 = ((X509Certificate)var3).getPublicKey();
         String var5 = ((X509Certificate)var3).getSigAlgName();
         AlgorithmParameters var6 = null;
         if (!var5.equals("1.2.156.10197.1.501")) {
            try {
               var3 = X509CertImpl.toImpl((X509Certificate)var1);
            } catch (CertificateException var14) {
               throw new CertPathValidatorException(var14);
            }

            AlgorithmId var7 = null;

            try {
               var7 = (AlgorithmId)((X509CertImpl)var3).get("x509.algorithm");
            } catch (CertificateException var13) {
               throw new CertPathValidatorException(var13);
            }

            var6 = var7.getParameters();
            if (!this.constraints.permits(SIGNATURE_PRIMITIVE_SET, var5, var6)) {
               throw new CertPathValidatorException("Algorithm constraints check failed: " + var5, (Throwable)null, (CertPath)null, -1, BasicReason.ALGORITHM_CONSTRAINED);
            }
         }

         boolean[] var15 = ((X509Certificate)var3).getKeyUsage();
         if (var15 != null && var15.length < 9) {
            throw new CertPathValidatorException("incorrect KeyUsage extension", (Throwable)null, (CertPath)null, -1, PKIXReason.INVALID_KEY_USAGE);
         } else {
            if (var15 != null) {
               EnumSet var8 = EnumSet.noneOf(CryptoPrimitive.class);
               if (var15[0] || var15[1] || var15[5] || var15[6]) {
                  var8.add(CryptoPrimitive.SIGNATURE);
               }

               if (var15[2]) {
                  var8.add(CryptoPrimitive.KEY_ENCAPSULATION);
               }

               if (var15[3]) {
                  var8.add(CryptoPrimitive.PUBLIC_KEY_ENCRYPTION);
               }

               if (var15[4]) {
                  var8.add(CryptoPrimitive.KEY_AGREEMENT);
               }

               if (!var8.isEmpty() && !this.constraints.permits(var8, var4)) {
                  throw new CertPathValidatorException("algorithm constraints check failed", (Throwable)null, (CertPath)null, -1, BasicReason.ALGORITHM_CONSTRAINED);
               }
            }

            if (this.prevPubKey != null) {
               if (!var5.equals("1.2.156.10197.1.501") && var5 != null && !this.constraints.permits(SIGNATURE_PRIMITIVE_SET, var5, this.prevPubKey, var6)) {
                  throw new CertPathValidatorException("Algorithm constraints check failed: " + var5, (Throwable)null, (CertPath)null, -1, BasicReason.ALGORITHM_CONSTRAINED);
               }

               if (var4 instanceof DSAPublicKey && ((DSAPublicKey)var4).getParams() == null) {
                  if (!(this.prevPubKey instanceof DSAPublicKey)) {
                     throw new CertPathValidatorException("Input key is not of a appropriate type for inheriting parameters");
                  }

                  DSAParams var16 = ((DSAPublicKey)this.prevPubKey).getParams();
                  if (var16 == null) {
                     throw new CertPathValidatorException("Key parameters missing");
                  }

                  try {
                     BigInteger var9 = ((DSAPublicKey)var4).getY();
                     KeyFactory var10 = KeyFactory.getInstance("DSA");
                     DSAPublicKeySpec var11 = new DSAPublicKeySpec(var9, var16.getP(), var16.getQ(), var16.getG());
                     var4 = var10.generatePublic(var11);
                  } catch (GeneralSecurityException var12) {
                     throw new CertPathValidatorException("Unable to generate key with inherited parameters: " + var12.getMessage(), var12);
                  }
               }
            }

            this.prevPubKey = var4;
         }
      }
   }

   void trySetTrustAnchor(TrustAnchor var1) {
      if (this.prevPubKey == null) {
         if (var1 == null) {
            throw new IllegalArgumentException("The trust anchor cannot be null");
         }

         if (var1.getTrustedCert() != null) {
            this.prevPubKey = var1.getTrustedCert().getPublicKey();
         } else {
            this.prevPubKey = var1.getCAPublicKey();
         }
      }

   }

   static void check(PublicKey var0, X509CRL var1) throws CertPathValidatorException {
      X509CRLImpl var2 = null;

      try {
         var2 = X509CRLImpl.toImpl(var1);
      } catch (CRLException var4) {
         throw new CertPathValidatorException(var4);
      }

      AlgorithmId var3 = var2.getSigAlgId();
      check(var0, var3);
   }

   static void check(PublicKey var0, AlgorithmId var1) throws CertPathValidatorException {
      String var2 = var1.getName();
      AlgorithmParameters var3 = var1.getParameters();
      if (!certPathDefaultConstraints.permits(SIGNATURE_PRIMITIVE_SET, var2, var0, var3)) {
         throw new CertPathValidatorException("algorithm check failed: " + var2 + " is disabled", (Throwable)null, (CertPath)null, -1, BasicReason.ALGORITHM_CONSTRAINED);
      }
   }
}
