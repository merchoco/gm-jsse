package org.bc.jce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.x509.CRLDistPoint;
import org.bc.asn1.x509.DistributionPoint;
import org.bc.asn1.x509.DistributionPointName;
import org.bc.asn1.x509.GeneralName;
import org.bc.asn1.x509.GeneralNames;
import org.bc.asn1.x509.ReasonFlags;
import org.bc.asn1.x509.TargetInformation;
import org.bc.asn1.x509.X509Extensions;
import org.bc.jce.exception.ExtCertPathValidatorException;
import org.bc.x509.ExtendedPKIXBuilderParameters;
import org.bc.x509.ExtendedPKIXParameters;
import org.bc.x509.PKIXAttrCertChecker;
import org.bc.x509.X509AttributeCertificate;
import org.bc.x509.X509CertStoreSelector;

class RFC3281CertPathUtilities {
   private static final String TARGET_INFORMATION;
   private static final String NO_REV_AVAIL;
   private static final String CRL_DISTRIBUTION_POINTS;
   private static final String AUTHORITY_INFO_ACCESS;

   static {
      TARGET_INFORMATION = X509Extensions.TargetInformation.getId();
      NO_REV_AVAIL = X509Extensions.NoRevAvail.getId();
      CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
      AUTHORITY_INFO_ACCESS = X509Extensions.AuthorityInfoAccess.getId();
   }

   protected static void processAttrCert7(X509AttributeCertificate var0, CertPath var1, CertPath var2, ExtendedPKIXParameters var3) throws CertPathValidatorException {
      Set var4 = var0.getCriticalExtensionOIDs();
      if (var4.contains(TARGET_INFORMATION)) {
         try {
            TargetInformation.getInstance(CertPathValidatorUtilities.getExtensionValue(var0, TARGET_INFORMATION));
         } catch (AnnotatedException var6) {
            throw new ExtCertPathValidatorException("Target information extension could not be read.", var6);
         } catch (IllegalArgumentException var7) {
            throw new ExtCertPathValidatorException("Target information extension could not be read.", var7);
         }
      }

      var4.remove(TARGET_INFORMATION);
      Iterator var5 = var3.getAttrCertCheckers().iterator();

      while(var5.hasNext()) {
         ((PKIXAttrCertChecker)var5.next()).check(var0, var1, var2, var4);
      }

      if (!var4.isEmpty()) {
         throw new CertPathValidatorException("Attribute certificate contains unsupported critical extensions: " + var4);
      }
   }

   protected static void checkCRLs(X509AttributeCertificate var0, ExtendedPKIXParameters var1, X509Certificate var2, Date var3, List var4) throws CertPathValidatorException {
      if (var1.isRevocationEnabled()) {
         if (var0.getExtensionValue(NO_REV_AVAIL) == null) {
            CRLDistPoint var5 = null;

            try {
               var5 = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var0, CRL_DISTRIBUTION_POINTS));
            } catch (AnnotatedException var17) {
               throw new CertPathValidatorException("CRL distribution point extension could not be read.", var17);
            }

            try {
               CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(var5, var1);
            } catch (AnnotatedException var16) {
               throw new CertPathValidatorException("No additional CRL locations could be decoded from CRL distribution point extension.", var16);
            }

            CertStatus var6 = new CertStatus();
            ReasonsMask var7 = new ReasonsMask();
            AnnotatedException var8 = null;
            boolean var9 = false;
            DistributionPoint[] var10;
            ExtendedPKIXParameters var12;
            if (var5 != null) {
               var10 = null;

               try {
                  var10 = var5.getDistributionPoints();
               } catch (Exception var15) {
                  throw new ExtCertPathValidatorException("Distribution points could not be read.", var15);
               }

               try {
                  for(int var11 = 0; var11 < var10.length && var6.getCertStatus() == 11 && !var7.isAllReasons(); ++var11) {
                     var12 = (ExtendedPKIXParameters)var1.clone();
                     checkCRL(var10[var11], var0, var12, var3, var2, var6, var7, var4);
                     var9 = true;
                  }
               } catch (AnnotatedException var18) {
                  var8 = new AnnotatedException("No valid CRL for distribution point found.", var18);
               }
            }

            if (var6.getCertStatus() == 11 && !var7.isAllReasons()) {
               try {
                  var10 = null;

                  ASN1Primitive var19;
                  try {
                     var19 = (new ASN1InputStream(((X500Principal)var0.getIssuer().getPrincipals()[0]).getEncoded())).readObject();
                  } catch (Exception var13) {
                     throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", var13);
                  }

                  DistributionPoint var21 = new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(4, var19))), (ReasonFlags)null, (GeneralNames)null);
                  var12 = (ExtendedPKIXParameters)var1.clone();
                  checkCRL(var21, var0, var12, var3, var2, var6, var7, var4);
                  var9 = true;
               } catch (AnnotatedException var14) {
                  var8 = new AnnotatedException("No valid CRL for distribution point found.", var14);
               }
            }

            if (!var9) {
               throw new ExtCertPathValidatorException("No valid CRL found.", var8);
            }

            if (var6.getCertStatus() != 11) {
               String var20 = "Attribute certificate revocation after " + var6.getRevocationDate();
               var20 = var20 + ", reason: " + RFC3280CertPathUtilities.crlReasons[var6.getCertStatus()];
               throw new CertPathValidatorException(var20);
            }

            if (!var7.isAllReasons() && var6.getCertStatus() == 11) {
               var6.setCertStatus(12);
            }

            if (var6.getCertStatus() == 12) {
               throw new CertPathValidatorException("Attribute certificate status could not be determined.");
            }
         } else if (var0.getExtensionValue(CRL_DISTRIBUTION_POINTS) != null || var0.getExtensionValue(AUTHORITY_INFO_ACCESS) != null) {
            throw new CertPathValidatorException("No rev avail extension is set, but also an AC revocation pointer.");
         }
      }

   }

   protected static void additionalChecks(X509AttributeCertificate var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      Iterator var2 = var1.getProhibitedACAttributes().iterator();

      String var3;
      while(var2.hasNext()) {
         var3 = (String)var2.next();
         if (var0.getAttributes(var3) != null) {
            throw new CertPathValidatorException("Attribute certificate contains prohibited attribute: " + var3 + ".");
         }
      }

      var2 = var1.getNecessaryACAttributes().iterator();

      while(var2.hasNext()) {
         var3 = (String)var2.next();
         if (var0.getAttributes(var3) == null) {
            throw new CertPathValidatorException("Attribute certificate does not contain necessary attribute: " + var3 + ".");
         }
      }

   }

   protected static void processAttrCert5(X509AttributeCertificate var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      try {
         var0.checkValidity(CertPathValidatorUtilities.getValidDate(var1));
      } catch (CertificateExpiredException var3) {
         throw new ExtCertPathValidatorException("Attribute certificate is not valid.", var3);
      } catch (CertificateNotYetValidException var4) {
         throw new ExtCertPathValidatorException("Attribute certificate is not valid.", var4);
      }
   }

   protected static void processAttrCert4(X509Certificate var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      Set var2 = var1.getTrustedACIssuers();
      boolean var3 = false;
      Iterator var4 = var2.iterator();

      while(true) {
         TrustAnchor var5;
         do {
            if (!var4.hasNext()) {
               if (!var3) {
                  throw new CertPathValidatorException("Attribute certificate issuer is not directly trusted.");
               }

               return;
            }

            var5 = (TrustAnchor)var4.next();
         } while(!var0.getSubjectX500Principal().getName("RFC2253").equals(var5.getCAName()) && !var0.equals(var5.getTrustedCert()));

         var3 = true;
      }
   }

   protected static void processAttrCert3(X509Certificate var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      if (var0.getKeyUsage() != null && !var0.getKeyUsage()[0] && !var0.getKeyUsage()[1]) {
         throw new CertPathValidatorException("Attribute certificate issuer public key cannot be used to validate digital signatures.");
      } else if (var0.getBasicConstraints() != -1) {
         throw new CertPathValidatorException("Attribute certificate issuer is also a public key certificate issuer.");
      }
   }

   protected static CertPathValidatorResult processAttrCert2(CertPath var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      CertPathValidator var2 = null;

      try {
         var2 = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
      } catch (NoSuchProviderException var6) {
         throw new ExtCertPathValidatorException("Support class could not be created.", var6);
      } catch (NoSuchAlgorithmException var7) {
         throw new ExtCertPathValidatorException("Support class could not be created.", var7);
      }

      try {
         return var2.validate(var0, var1);
      } catch (CertPathValidatorException var4) {
         throw new ExtCertPathValidatorException("Certification path for issuer certificate of attribute certificate could not be validated.", var4);
      } catch (InvalidAlgorithmParameterException var5) {
         throw new RuntimeException(var5.getMessage());
      }
   }

   protected static CertPath processAttrCert1(X509AttributeCertificate var0, ExtendedPKIXParameters var1) throws CertPathValidatorException {
      CertPathBuilderResult var2 = null;
      HashSet var3 = new HashSet();
      X509CertStoreSelector var4;
      Principal[] var5;
      int var6;
      if (var0.getHolder().getIssuer() != null) {
         var4 = new X509CertStoreSelector();
         var4.setSerialNumber(var0.getHolder().getSerialNumber());
         var5 = var0.getHolder().getIssuer();

         for(var6 = 0; var6 < var5.length; ++var6) {
            try {
               if (var5[var6] instanceof X500Principal) {
                  var4.setIssuer(((X500Principal)var5[var6]).getEncoded());
               }

               var3.addAll(CertPathValidatorUtilities.findCertificates(var4, var1.getStores()));
            } catch (AnnotatedException var16) {
               throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", var16);
            } catch (IOException var17) {
               throw new ExtCertPathValidatorException("Unable to encode X500 principal.", var17);
            }
         }

         if (var3.isEmpty()) {
            throw new CertPathValidatorException("Public key certificate specified in base certificate ID for attribute certificate cannot be found.");
         }
      }

      if (var0.getHolder().getEntityNames() != null) {
         var4 = new X509CertStoreSelector();
         var5 = var0.getHolder().getEntityNames();

         for(var6 = 0; var6 < var5.length; ++var6) {
            try {
               if (var5[var6] instanceof X500Principal) {
                  var4.setIssuer(((X500Principal)var5[var6]).getEncoded());
               }

               var3.addAll(CertPathValidatorUtilities.findCertificates(var4, var1.getStores()));
            } catch (AnnotatedException var14) {
               throw new ExtCertPathValidatorException("Public key certificate for attribute certificate cannot be searched.", var14);
            } catch (IOException var15) {
               throw new ExtCertPathValidatorException("Unable to encode X500 principal.", var15);
            }
         }

         if (var3.isEmpty()) {
            throw new CertPathValidatorException("Public key certificate specified in entity name for attribute certificate cannot be found.");
         }
      }

      ExtendedPKIXBuilderParameters var18 = (ExtendedPKIXBuilderParameters)ExtendedPKIXBuilderParameters.getInstance(var1);
      ExtCertPathValidatorException var19 = null;
      Iterator var20 = var3.iterator();

      while(var20.hasNext()) {
         X509CertStoreSelector var7 = new X509CertStoreSelector();
         var7.setCertificate((X509Certificate)var20.next());
         var18.setTargetConstraints(var7);
         CertPathBuilder var8 = null;

         try {
            var8 = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
         } catch (NoSuchProviderException var12) {
            throw new ExtCertPathValidatorException("Support class could not be created.", var12);
         } catch (NoSuchAlgorithmException var13) {
            throw new ExtCertPathValidatorException("Support class could not be created.", var13);
         }

         try {
            var2 = var8.build(ExtendedPKIXBuilderParameters.getInstance(var18));
         } catch (CertPathBuilderException var10) {
            var19 = new ExtCertPathValidatorException("Certification path for public key certificate of attribute certificate could not be build.", var10);
         } catch (InvalidAlgorithmParameterException var11) {
            throw new RuntimeException(var11.getMessage());
         }
      }

      if (var19 != null) {
         throw var19;
      } else {
         return var2.getCertPath();
      }
   }

   private static void checkCRL(DistributionPoint var0, X509AttributeCertificate var1, ExtendedPKIXParameters var2, Date var3, X509Certificate var4, CertStatus var5, ReasonsMask var6, List var7) throws AnnotatedException {
      if (var1.getExtensionValue(X509Extensions.NoRevAvail.getId()) == null) {
         Date var8 = new Date(System.currentTimeMillis());
         if (var3.getTime() > var8.getTime()) {
            throw new AnnotatedException("Validation time is in future.");
         } else {
            Set var9 = CertPathValidatorUtilities.getCompleteCRLs(var0, var1, var8, var2);
            boolean var10 = false;
            AnnotatedException var11 = null;
            Iterator var12 = var9.iterator();

            while(var12.hasNext() && var5.getCertStatus() == 11 && !var6.isAllReasons()) {
               try {
                  X509CRL var13 = (X509CRL)var12.next();
                  ReasonsMask var14 = RFC3280CertPathUtilities.processCRLD(var13, var0);
                  if (var14.hasNewReasons(var6)) {
                     Set var15 = RFC3280CertPathUtilities.processCRLF(var13, var1, (X509Certificate)null, (PublicKey)null, var2, var7);
                     PublicKey var16 = RFC3280CertPathUtilities.processCRLG(var13, var15);
                     X509CRL var17 = null;
                     if (var2.isUseDeltasEnabled()) {
                        Set var18 = CertPathValidatorUtilities.getDeltaCRLs(var8, var2, var13);
                        var17 = RFC3280CertPathUtilities.processCRLH(var18, var16);
                     }

                     if (var2.getValidityModel() != 1 && var1.getNotAfter().getTime() < var13.getThisUpdate().getTime()) {
                        throw new AnnotatedException("No valid CRL for current time found.");
                     }

                     RFC3280CertPathUtilities.processCRLB1(var0, var1, var13);
                     RFC3280CertPathUtilities.processCRLB2(var0, var1, var13);
                     RFC3280CertPathUtilities.processCRLC(var17, var13, var2);
                     RFC3280CertPathUtilities.processCRLI(var3, var17, var1, var5, var2);
                     RFC3280CertPathUtilities.processCRLJ(var3, var13, var1, var5);
                     if (var5.getCertStatus() == 8) {
                        var5.setCertStatus(11);
                     }

                     var6.addReasons(var14);
                     var10 = true;
                  }
               } catch (AnnotatedException var19) {
                  var11 = var19;
               }
            }

            if (!var10) {
               throw var11;
            }
         }
      }
   }
}
