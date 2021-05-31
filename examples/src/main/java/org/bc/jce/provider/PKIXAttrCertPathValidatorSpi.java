package org.bc.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bc.jce.exception.ExtCertPathValidatorException;
import org.bc.util.Selector;
import org.bc.x509.ExtendedPKIXParameters;
import org.bc.x509.X509AttributeCertStoreSelector;
import org.bc.x509.X509AttributeCertificate;

public class PKIXAttrCertPathValidatorSpi extends CertPathValidatorSpi {
   public CertPathValidatorResult engineValidate(CertPath var1, CertPathParameters var2) throws CertPathValidatorException, InvalidAlgorithmParameterException {
      if (!(var2 instanceof ExtendedPKIXParameters)) {
         throw new InvalidAlgorithmParameterException("Parameters must be a " + ExtendedPKIXParameters.class.getName() + " instance.");
      } else {
         ExtendedPKIXParameters var3 = (ExtendedPKIXParameters)var2;
         Selector var4 = var3.getTargetConstraints();
         if (!(var4 instanceof X509AttributeCertStoreSelector)) {
            throw new InvalidAlgorithmParameterException("TargetConstraints must be an instance of " + X509AttributeCertStoreSelector.class.getName() + " for " + this.getClass().getName() + " class.");
         } else {
            X509AttributeCertificate var5 = ((X509AttributeCertStoreSelector)var4).getAttributeCert();
            CertPath var6 = RFC3281CertPathUtilities.processAttrCert1(var5, var3);
            CertPathValidatorResult var7 = RFC3281CertPathUtilities.processAttrCert2(var1, var3);
            X509Certificate var8 = (X509Certificate)var1.getCertificates().get(0);
            RFC3281CertPathUtilities.processAttrCert3(var8, var3);
            RFC3281CertPathUtilities.processAttrCert4(var8, var3);
            RFC3281CertPathUtilities.processAttrCert5(var5, var3);
            RFC3281CertPathUtilities.processAttrCert7(var5, var1, var6, var3);
            RFC3281CertPathUtilities.additionalChecks(var5, var3);
            Date var9 = null;

            try {
               var9 = CertPathValidatorUtilities.getValidCertDateFromValidityModel(var3, (CertPath)null, -1);
            } catch (AnnotatedException var11) {
               throw new ExtCertPathValidatorException("Could not get validity date from attribute certificate.", var11);
            }

            RFC3281CertPathUtilities.checkCRLs(var5, var3, var8, var9, var1.getCertificates());
            return var7;
         }
      }
   }
}
