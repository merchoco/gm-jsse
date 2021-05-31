package org.bc.jce.provider;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Principal;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bc.jce.exception.ExtCertPathBuilderException;
import org.bc.util.Selector;
import org.bc.x509.ExtendedPKIXBuilderParameters;
import org.bc.x509.X509AttributeCertStoreSelector;
import org.bc.x509.X509AttributeCertificate;
import org.bc.x509.X509CertStoreSelector;

public class PKIXAttrCertPathBuilderSpi extends CertPathBuilderSpi {
   private Exception certPathException;

   public CertPathBuilderResult engineBuild(CertPathParameters var1) throws CertPathBuilderException, InvalidAlgorithmParameterException {
      if (!(var1 instanceof PKIXBuilderParameters) && !(var1 instanceof ExtendedPKIXBuilderParameters)) {
         throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + ExtendedPKIXBuilderParameters.class.getName() + ".");
      } else {
         ExtendedPKIXBuilderParameters var2;
         if (var1 instanceof ExtendedPKIXBuilderParameters) {
            var2 = (ExtendedPKIXBuilderParameters)var1;
         } else {
            var2 = (ExtendedPKIXBuilderParameters)ExtendedPKIXBuilderParameters.getInstance((PKIXBuilderParameters)var1);
         }

         ArrayList var5 = new ArrayList();
         Selector var7 = var2.getTargetConstraints();
         if (!(var7 instanceof X509AttributeCertStoreSelector)) {
            throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + this.getClass().getName() + " class.");
         } else {
            Collection var3;
            try {
               var3 = CertPathValidatorUtilities.findCertificates((X509AttributeCertStoreSelector)var7, var2.getStores());
            } catch (AnnotatedException var14) {
               throw new ExtCertPathBuilderException("Error finding target attribute certificate.", var14);
            }

            if (var3.isEmpty()) {
               throw new CertPathBuilderException("No attribute certificate found matching targetContraints.");
            } else {
               CertPathBuilderResult var8 = null;
               Iterator var4 = var3.iterator();

               while(var4.hasNext() && var8 == null) {
                  X509AttributeCertificate var6 = (X509AttributeCertificate)var4.next();
                  X509CertStoreSelector var9 = new X509CertStoreSelector();
                  Principal[] var10 = var6.getIssuer().getPrincipals();
                  HashSet var11 = new HashSet();

                  for(int var12 = 0; var12 < var10.length; ++var12) {
                     try {
                        if (var10[var12] instanceof X500Principal) {
                           var9.setSubject(((X500Principal)var10[var12]).getEncoded());
                        }

                        var11.addAll(CertPathValidatorUtilities.findCertificates(var9, var2.getStores()));
                        var11.addAll(CertPathValidatorUtilities.findCertificates(var9, var2.getCertStores()));
                     } catch (AnnotatedException var15) {
                        throw new ExtCertPathBuilderException("Public key certificate for attribute certificate cannot be searched.", var15);
                     } catch (IOException var16) {
                        throw new ExtCertPathBuilderException("cannot encode X500Principal.", var16);
                     }
                  }

                  if (var11.isEmpty()) {
                     throw new CertPathBuilderException("Public key certificate for attribute certificate cannot be found.");
                  }

                  for(Iterator var17 = var11.iterator(); var17.hasNext() && var8 == null; var8 = this.build(var6, (X509Certificate)var17.next(), var2, var5)) {
                     ;
                  }
               }

               if (var8 == null && this.certPathException != null) {
                  throw new ExtCertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
               } else if (var8 == null && this.certPathException == null) {
                  throw new CertPathBuilderException("Unable to find certificate chain.");
               } else {
                  return var8;
               }
            }
         }
      }
   }

   private CertPathBuilderResult build(X509AttributeCertificate var1, X509Certificate var2, ExtendedPKIXBuilderParameters var3, List var4) {
      if (var4.contains(var2)) {
         return null;
      } else if (var3.getExcludedCerts().contains(var2)) {
         return null;
      } else if (var3.getMaxPathLength() != -1 && var4.size() - 1 > var3.getMaxPathLength()) {
         return null;
      } else {
         var4.add(var2);
         CertPathBuilderResult var7 = null;

         CertificateFactory var5;
         CertPathValidator var6;
         try {
            var5 = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            var6 = CertPathValidator.getInstance("RFC3281", BouncyCastleProvider.PROVIDER_NAME);
         } catch (Exception var15) {
            throw new RuntimeException("Exception creating support classes.");
         }

         try {
            if (CertPathValidatorUtilities.findTrustAnchor(var2, var3.getTrustAnchors(), var3.getSigProvider()) != null) {
               CertPath var17;
               try {
                  var17 = var5.generateCertPath(var4);
               } catch (Exception var12) {
                  throw new AnnotatedException("Certification path could not be constructed from certificate list.", var12);
               }

               PKIXCertPathValidatorResult var18;
               try {
                  var18 = (PKIXCertPathValidatorResult)var6.validate(var17, var3);
               } catch (Exception var11) {
                  throw new AnnotatedException("Certification path could not be validated.", var11);
               }

               return new PKIXCertPathBuilderResult(var17, var18.getTrustAnchor(), var18.getPolicyTree(), var18.getPublicKey());
            }

            try {
               CertPathValidatorUtilities.addAdditionalStoresFromAltNames(var2, var3);
            } catch (CertificateParsingException var14) {
               throw new AnnotatedException("No additional X.509 stores can be added from certificate locations.", var14);
            }

            HashSet var8 = new HashSet();

            try {
               var8.addAll(CertPathValidatorUtilities.findIssuerCerts(var2, var3));
            } catch (AnnotatedException var13) {
               throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", var13);
            }

            if (var8.isEmpty()) {
               throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
            }

            Iterator var9 = var8.iterator();

            while(var9.hasNext() && var7 == null) {
               X509Certificate var10 = (X509Certificate)var9.next();
               if (!var10.getIssuerX500Principal().equals(var10.getSubjectX500Principal())) {
                  var7 = this.build(var1, var10, var3, var4);
               }
            }
         } catch (AnnotatedException var16) {
            this.certPathException = new AnnotatedException("No valid certification path could be build.", var16);
         }

         if (var7 == null) {
            var4.remove(var2);
         }

         return var7;
      }
   }
}
