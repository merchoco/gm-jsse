package org.bc.jce.provider;

import java.security.InvalidAlgorithmParameterException;
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
import org.bc.jce.exception.ExtCertPathBuilderException;
import org.bc.util.Selector;
import org.bc.x509.ExtendedPKIXBuilderParameters;
import org.bc.x509.X509CertStoreSelector;

public class PKIXCertPathBuilderSpi extends CertPathBuilderSpi {
   private Exception certPathException;

   public CertPathBuilderResult engineBuild(CertPathParameters var1) throws CertPathBuilderException, InvalidAlgorithmParameterException {
      if (!(var1 instanceof PKIXBuilderParameters) && !(var1 instanceof ExtendedPKIXBuilderParameters)) {
         throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + ExtendedPKIXBuilderParameters.class.getName() + ".");
      } else {
         ExtendedPKIXBuilderParameters var2 = null;
         if (var1 instanceof ExtendedPKIXBuilderParameters) {
            var2 = (ExtendedPKIXBuilderParameters)var1;
         } else {
            var2 = (ExtendedPKIXBuilderParameters)ExtendedPKIXBuilderParameters.getInstance((PKIXBuilderParameters)var1);
         }

         ArrayList var5 = new ArrayList();
         Selector var7 = var2.getTargetConstraints();
         if (!(var7 instanceof X509CertStoreSelector)) {
            throw new CertPathBuilderException("TargetConstraints must be an instance of " + X509CertStoreSelector.class.getName() + " for " + this.getClass().getName() + " class.");
         } else {
            Collection var3;
            try {
               var3 = CertPathValidatorUtilities.findCertificates((X509CertStoreSelector)var7, var2.getStores());
               var3.addAll(CertPathValidatorUtilities.findCertificates((X509CertStoreSelector)var7, var2.getCertStores()));
            } catch (AnnotatedException var9) {
               throw new ExtCertPathBuilderException("Error finding target certificate.", var9);
            }

            if (var3.isEmpty()) {
               throw new CertPathBuilderException("No certificate found matching targetContraints.");
            } else {
               CertPathBuilderResult var8 = null;

               X509Certificate var6;
               for(Iterator var4 = var3.iterator(); var4.hasNext() && var8 == null; var8 = this.build(var6, var2, var5)) {
                  var6 = (X509Certificate)var4.next();
               }

               if (var8 == null && this.certPathException != null) {
                  if (this.certPathException instanceof AnnotatedException) {
                     throw new CertPathBuilderException(this.certPathException.getMessage(), this.certPathException.getCause());
                  } else {
                     throw new CertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
                  }
               } else if (var8 == null && this.certPathException == null) {
                  throw new CertPathBuilderException("Unable to find certificate chain.");
               } else {
                  return var8;
               }
            }
         }
      }
   }

   protected CertPathBuilderResult build(X509Certificate var1, ExtendedPKIXBuilderParameters var2, List var3) {
      if (var3.contains(var1)) {
         return null;
      } else if (var2.getExcludedCerts().contains(var1)) {
         return null;
      } else if (var2.getMaxPathLength() != -1 && var3.size() - 1 > var2.getMaxPathLength()) {
         return null;
      } else {
         var3.add(var1);
         CertPathBuilderResult var6 = null;

         CertificateFactory var4;
         CertPathValidator var5;
         try {
            var4 = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            var5 = CertPathValidator.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
         } catch (Exception var14) {
            throw new RuntimeException("Exception creating support classes.");
         }

         try {
            HashSet var7;
            Iterator var8;
            if (CertPathValidatorUtilities.findTrustAnchor(var1, var2.getTrustAnchors(), var2.getSigProvider()) != null) {
               var7 = null;
               var8 = null;

               CertPath var16;
               try {
                  var16 = var4.generateCertPath(var3);
               } catch (Exception var11) {
                  throw new AnnotatedException("Certification path could not be constructed from certificate list.", var11);
               }

               PKIXCertPathValidatorResult var17;
               try {
                  var17 = (PKIXCertPathValidatorResult)var5.validate(var16, var2);
               } catch (Exception var10) {
                  throw new AnnotatedException("Certification path could not be validated.", var10);
               }

               return new PKIXCertPathBuilderResult(var16, var17.getTrustAnchor(), var17.getPolicyTree(), var17.getPublicKey());
            }

            try {
               CertPathValidatorUtilities.addAdditionalStoresFromAltNames(var1, var2);
            } catch (CertificateParsingException var13) {
               throw new AnnotatedException("No additiontal X.509 stores can be added from certificate locations.", var13);
            }

            var7 = new HashSet();

            try {
               var7.addAll(CertPathValidatorUtilities.findIssuerCerts(var1, var2));
            } catch (AnnotatedException var12) {
               throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", var12);
            }

            if (var7.isEmpty()) {
               throw new AnnotatedException("No issuer certificate for certificate in certification path found.");
            }

            X509Certificate var9;
            for(var8 = var7.iterator(); var8.hasNext() && var6 == null; var6 = this.build(var9, var2, var3)) {
               var9 = (X509Certificate)var8.next();
            }
         } catch (AnnotatedException var15) {
            this.certPathException = var15;
         }

         if (var6 == null) {
            var3.remove(var1);
         }

         return var6;
      }
   }
}
