package org.bc.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.jce.exception.ExtCertPathValidatorException;
import org.bc.x509.ExtendedPKIXParameters;

public class PKIXCertPathValidatorSpi extends CertPathValidatorSpi {
   public CertPathValidatorResult engineValidate(CertPath var1, CertPathParameters var2) throws CertPathValidatorException, InvalidAlgorithmParameterException {
      if (!(var2 instanceof PKIXParameters)) {
         throw new InvalidAlgorithmParameterException("Parameters must be a " + PKIXParameters.class.getName() + " instance.");
      } else {
         ExtendedPKIXParameters var3;
         if (var2 instanceof ExtendedPKIXParameters) {
            var3 = (ExtendedPKIXParameters)var2;
         } else {
            var3 = ExtendedPKIXParameters.getInstance((PKIXParameters)var2);
         }

         if (var3.getTrustAnchors() == null) {
            throw new InvalidAlgorithmParameterException("trustAnchors is null, this is not allowed for certification path validation.");
         } else {
            List var4 = var1.getCertificates();
            int var5 = var4.size();
            if (var4.isEmpty()) {
               throw new CertPathValidatorException("Certification path is empty.", (Throwable)null, var1, 0);
            } else {
               Set var6 = var3.getInitialPolicies();

               TrustAnchor var7;
               try {
                  var7 = CertPathValidatorUtilities.findTrustAnchor((X509Certificate)var4.get(var4.size() - 1), var3.getTrustAnchors(), var3.getSigProvider());
               } catch (AnnotatedException var34) {
                  throw new CertPathValidatorException(var34.getMessage(), var34, var1, var4.size() - 1);
               }

               if (var7 == null) {
                  throw new CertPathValidatorException("Trust anchor for certification path not found.", (Throwable)null, var1, -1);
               } else {
                  boolean var9 = false;
                  ArrayList[] var11 = new ArrayList[var5 + 1];

                  for(int var12 = 0; var12 < var11.length; ++var12) {
                     var11[var12] = new ArrayList();
                  }

                  HashSet var36 = new HashSet();
                  var36.add("2.5.29.32.0");
                  PKIXPolicyNode var13 = new PKIXPolicyNode(new ArrayList(), 0, var36, (PolicyNode)null, new HashSet(), "2.5.29.32.0", false);
                  var11[0].add(var13);
                  PKIXNameConstraintValidator var14 = new PKIXNameConstraintValidator();
                  HashSet var16 = new HashSet();
                  int var15;
                  if (var3.isExplicitPolicyRequired()) {
                     var15 = 0;
                  } else {
                     var15 = var5 + 1;
                  }

                  int var17;
                  if (var3.isAnyPolicyInhibited()) {
                     var17 = 0;
                  } else {
                     var17 = var5 + 1;
                  }

                  int var18;
                  if (var3.isPolicyMappingInhibited()) {
                     var18 = 0;
                  } else {
                     var18 = var5 + 1;
                  }

                  X509Certificate var21 = var7.getTrustedCert();

                  PublicKey var19;
                  X500Principal var20;
                  try {
                     if (var21 != null) {
                        var20 = CertPathValidatorUtilities.getSubjectPrincipal(var21);
                        var19 = var21.getPublicKey();
                     } else {
                        var20 = new X500Principal(var7.getCAName());
                        var19 = var7.getCAPublicKey();
                     }
                  } catch (IllegalArgumentException var33) {
                     throw new ExtCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", var33, var1, -1);
                  }

                  AlgorithmIdentifier var22 = null;

                  try {
                     var22 = CertPathValidatorUtilities.getAlgorithmIdentifier(var19);
                  } catch (CertPathValidatorException var32) {
                     throw new ExtCertPathValidatorException("Algorithm identifier of public key of trust anchor could not be read.", var32, var1, -1);
                  }

                  ASN1ObjectIdentifier var23 = var22.getObjectId();
                  ASN1Encodable var24 = var22.getParameters();
                  int var25 = var5;
                  if (var3.getTargetConstraints() != null && !var3.getTargetConstraints().match((X509Certificate)var4.get(0))) {
                     throw new ExtCertPathValidatorException("Target certificate in certification path does not match targetConstraints.", (Throwable)null, var1, 0);
                  } else {
                     List var26 = var3.getCertPathCheckers();
                     Iterator var8 = var26.iterator();

                     while(var8.hasNext()) {
                        ((PKIXCertPathChecker)var8.next()).init(false);
                     }

                     X509Certificate var27 = null;

                     int var35;
                     for(var35 = var4.size() - 1; var35 >= 0; --var35) {
                        int var10 = var5 - var35;
                        var27 = (X509Certificate)var4.get(var35);
                        boolean var28 = var35 == var4.size() - 1;
                        RFC3280CertPathUtilities.processCertA(var1, var3, var35, var19, var28, var20, var21);
                        RFC3280CertPathUtilities.processCertBC(var1, var35, var14);
                        var13 = RFC3280CertPathUtilities.processCertD(var1, var35, var16, var13, var11, var17);
                        var13 = RFC3280CertPathUtilities.processCertE(var1, var35, var13);
                        RFC3280CertPathUtilities.processCertF(var1, var35, var13, var15);
                        if (var10 != var5) {
                           if (var27 != null && var27.getVersion() == 1) {
                              throw new CertPathValidatorException("Version 1 certificates can't be used as CA ones.", (Throwable)null, var1, var35);
                           }

                           RFC3280CertPathUtilities.prepareNextCertA(var1, var35);
                           var13 = RFC3280CertPathUtilities.prepareCertB(var1, var35, var11, var13, var18);
                           RFC3280CertPathUtilities.prepareNextCertG(var1, var35, var14);
                           var15 = RFC3280CertPathUtilities.prepareNextCertH1(var1, var35, var15);
                           var18 = RFC3280CertPathUtilities.prepareNextCertH2(var1, var35, var18);
                           var17 = RFC3280CertPathUtilities.prepareNextCertH3(var1, var35, var17);
                           var15 = RFC3280CertPathUtilities.prepareNextCertI1(var1, var35, var15);
                           var18 = RFC3280CertPathUtilities.prepareNextCertI2(var1, var35, var18);
                           var17 = RFC3280CertPathUtilities.prepareNextCertJ(var1, var35, var17);
                           RFC3280CertPathUtilities.prepareNextCertK(var1, var35);
                           var25 = RFC3280CertPathUtilities.prepareNextCertL(var1, var35, var25);
                           var25 = RFC3280CertPathUtilities.prepareNextCertM(var1, var35, var25);
                           RFC3280CertPathUtilities.prepareNextCertN(var1, var35);
                           Set var29 = var27.getCriticalExtensionOIDs();
                           HashSet var39;
                           if (var29 != null) {
                              var39 = new HashSet(var29);
                              var39.remove(RFC3280CertPathUtilities.KEY_USAGE);
                              var39.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                              var39.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                              var39.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                              var39.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                              var39.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                              var39.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                              var39.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                              var39.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                              var39.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                           } else {
                              var39 = new HashSet();
                           }

                           RFC3280CertPathUtilities.prepareNextCertO(var1, var35, var39, var26);
                           var21 = var27;
                           var20 = CertPathValidatorUtilities.getSubjectPrincipal(var27);

                           try {
                              var19 = CertPathValidatorUtilities.getNextWorkingKey(var1.getCertificates(), var35);
                           } catch (CertPathValidatorException var31) {
                              throw new CertPathValidatorException("Next working key could not be retrieved.", var31, var1, var35);
                           }

                           var22 = CertPathValidatorUtilities.getAlgorithmIdentifier(var19);
                           var23 = var22.getObjectId();
                           var24 = var22.getParameters();
                        }
                     }

                     var15 = RFC3280CertPathUtilities.wrapupCertA(var15, var27);
                     var15 = RFC3280CertPathUtilities.wrapupCertB(var1, var35 + 1, var15);
                     Set var37 = var27.getCriticalExtensionOIDs();
                     HashSet var38;
                     if (var37 != null) {
                        var38 = new HashSet(var37);
                        var38.remove(RFC3280CertPathUtilities.KEY_USAGE);
                        var38.remove(RFC3280CertPathUtilities.CERTIFICATE_POLICIES);
                        var38.remove(RFC3280CertPathUtilities.POLICY_MAPPINGS);
                        var38.remove(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY);
                        var38.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
                        var38.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
                        var38.remove(RFC3280CertPathUtilities.POLICY_CONSTRAINTS);
                        var38.remove(RFC3280CertPathUtilities.BASIC_CONSTRAINTS);
                        var38.remove(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME);
                        var38.remove(RFC3280CertPathUtilities.NAME_CONSTRAINTS);
                        var38.remove(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS);
                     } else {
                        var38 = new HashSet();
                     }

                     RFC3280CertPathUtilities.wrapupCertF(var1, var35 + 1, var26, var38);
                     PKIXPolicyNode var40 = RFC3280CertPathUtilities.wrapupCertG(var1, var3, var6, var35 + 1, var11, var13, var16);
                     if (var15 <= 0 && var40 == null) {
                        throw new CertPathValidatorException("Path processing failed on policy.", (Throwable)null, var1, var35);
                     } else {
                        return new PKIXCertPathValidatorResult(var7, var40, var27.getPublicKey());
                     }
                  }
               }
            }
         }
      }
   }
}
