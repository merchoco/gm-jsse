package org.bc.jce.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERInteger;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.BasicConstraints;
import org.bc.asn1.x509.CRLDistPoint;
import org.bc.asn1.x509.DistributionPoint;
import org.bc.asn1.x509.DistributionPointName;
import org.bc.asn1.x509.GeneralName;
import org.bc.asn1.x509.GeneralNames;
import org.bc.asn1.x509.GeneralSubtree;
import org.bc.asn1.x509.IssuingDistributionPoint;
import org.bc.asn1.x509.NameConstraints;
import org.bc.asn1.x509.PolicyInformation;
import org.bc.asn1.x509.ReasonFlags;
import org.bc.asn1.x509.X509Extensions;
import org.bc.asn1.x509.X509Name;
import org.bc.jce.exception.ExtCertPathValidatorException;
import org.bc.util.Arrays;
import org.bc.x509.ExtendedPKIXBuilderParameters;
import org.bc.x509.ExtendedPKIXParameters;
import org.bc.x509.X509CRLStoreSelector;
import org.bc.x509.X509CertStoreSelector;

public class RFC3280CertPathUtilities {
   private static final PKIXCRLUtil CRL_UTIL = new PKIXCRLUtil();
   protected static final String CERTIFICATE_POLICIES;
   protected static final String POLICY_MAPPINGS;
   protected static final String INHIBIT_ANY_POLICY;
   protected static final String ISSUING_DISTRIBUTION_POINT;
   protected static final String FRESHEST_CRL;
   protected static final String DELTA_CRL_INDICATOR;
   protected static final String POLICY_CONSTRAINTS;
   protected static final String BASIC_CONSTRAINTS;
   protected static final String CRL_DISTRIBUTION_POINTS;
   protected static final String SUBJECT_ALTERNATIVE_NAME;
   protected static final String NAME_CONSTRAINTS;
   protected static final String AUTHORITY_KEY_IDENTIFIER;
   protected static final String KEY_USAGE;
   protected static final String CRL_NUMBER;
   protected static final String ANY_POLICY = "2.5.29.32.0";
   protected static final int KEY_CERT_SIGN = 5;
   protected static final int CRL_SIGN = 6;
   protected static final String[] crlReasons;

   static {
      CERTIFICATE_POLICIES = X509Extensions.CertificatePolicies.getId();
      POLICY_MAPPINGS = X509Extensions.PolicyMappings.getId();
      INHIBIT_ANY_POLICY = X509Extensions.InhibitAnyPolicy.getId();
      ISSUING_DISTRIBUTION_POINT = X509Extensions.IssuingDistributionPoint.getId();
      FRESHEST_CRL = X509Extensions.FreshestCRL.getId();
      DELTA_CRL_INDICATOR = X509Extensions.DeltaCRLIndicator.getId();
      POLICY_CONSTRAINTS = X509Extensions.PolicyConstraints.getId();
      BASIC_CONSTRAINTS = X509Extensions.BasicConstraints.getId();
      CRL_DISTRIBUTION_POINTS = X509Extensions.CRLDistributionPoints.getId();
      SUBJECT_ALTERNATIVE_NAME = X509Extensions.SubjectAlternativeName.getId();
      NAME_CONSTRAINTS = X509Extensions.NameConstraints.getId();
      AUTHORITY_KEY_IDENTIFIER = X509Extensions.AuthorityKeyIdentifier.getId();
      KEY_USAGE = X509Extensions.KeyUsage.getId();
      CRL_NUMBER = X509Extensions.CRLNumber.getId();
      crlReasons = new String[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};
   }

   protected static void processCRLB2(DistributionPoint var0, Object var1, X509CRL var2) throws AnnotatedException {
      IssuingDistributionPoint var3 = null;

      try {
         var3 = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var2, ISSUING_DISTRIBUTION_POINT));
      } catch (Exception var13) {
         throw new AnnotatedException("Issuing distribution point extension could not be decoded.", var13);
      }

      if (var3 != null) {
         DistributionPointName var4;
         if (var3.getDistributionPoint() != null) {
            var4 = IssuingDistributionPoint.getInstance(var3).getDistributionPoint();
            ArrayList var5 = new ArrayList();
            if (var4.getType() == 0) {
               GeneralName[] var6 = GeneralNames.getInstance(var4.getName()).getNames();

               for(int var7 = 0; var7 < var6.length; ++var7) {
                  var5.add(var6[var7]);
               }
            }

            if (var4.getType() == 1) {
               ASN1EncodableVector var16 = new ASN1EncodableVector();

               try {
                  Enumeration var18 = ASN1Sequence.getInstance(ASN1Sequence.fromByteArray(CertPathValidatorUtilities.getIssuerPrincipal(var2).getEncoded())).getObjects();

                  while(var18.hasMoreElements()) {
                     var16.add((ASN1Encodable)var18.nextElement());
                  }
               } catch (IOException var14) {
                  throw new AnnotatedException("Could not read CRL issuer.", var14);
               }

               var16.add(var4.getName());
               var5.add(new GeneralName(X509Name.getInstance(new DERSequence(var16))));
            }

            boolean var17 = false;
            int var8;
            GeneralName[] var19;
            if (var0.getDistributionPoint() != null) {
               var4 = var0.getDistributionPoint();
               var19 = null;
               if (var4.getType() == 0) {
                  var19 = GeneralNames.getInstance(var4.getName()).getNames();
               }

               if (var4.getType() == 1) {
                  if (var0.getCRLIssuer() != null) {
                     var19 = var0.getCRLIssuer().getNames();
                  } else {
                     var19 = new GeneralName[1];

                     try {
                        var19[0] = new GeneralName(new X509Name((ASN1Sequence)ASN1Sequence.fromByteArray(CertPathValidatorUtilities.getEncodedIssuerPrincipal(var1).getEncoded())));
                     } catch (IOException var12) {
                        throw new AnnotatedException("Could not read certificate issuer.", var12);
                     }
                  }

                  for(var8 = 0; var8 < var19.length; ++var8) {
                     Enumeration var9 = ASN1Sequence.getInstance(var19[var8].getName().toASN1Primitive()).getObjects();
                     ASN1EncodableVector var10 = new ASN1EncodableVector();

                     while(var9.hasMoreElements()) {
                        var10.add((ASN1Encodable)var9.nextElement());
                     }

                     var10.add(var4.getName());
                     var19[var8] = new GeneralName(new X509Name(new DERSequence(var10)));
                  }
               }

               if (var19 != null) {
                  for(var8 = 0; var8 < var19.length; ++var8) {
                     if (var5.contains(var19[var8])) {
                        var17 = true;
                        break;
                     }
                  }
               }

               if (!var17) {
                  throw new AnnotatedException("No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
               }
            } else {
               if (var0.getCRLIssuer() == null) {
                  throw new AnnotatedException("Either the cRLIssuer or the distributionPoint field must be contained in DistributionPoint.");
               }

               var19 = var0.getCRLIssuer().getNames();

               for(var8 = 0; var8 < var19.length; ++var8) {
                  if (var5.contains(var19[var8])) {
                     var17 = true;
                     break;
                  }
               }

               if (!var17) {
                  throw new AnnotatedException("No match for certificate CRL issuing distribution point name to cRLIssuer CRL distribution point.");
               }
            }
         }

         var4 = null;

         BasicConstraints var15;
         try {
            var15 = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue((X509Extension)var1, BASIC_CONSTRAINTS));
         } catch (Exception var11) {
            throw new AnnotatedException("Basic constraints extension could not be decoded.", var11);
         }

         if (var1 instanceof X509Certificate) {
            if (var3.onlyContainsUserCerts() && var15 != null && var15.isCA()) {
               throw new AnnotatedException("CA Cert CRL only contains user certificates.");
            }

            if (var3.onlyContainsCACerts() && (var15 == null || !var15.isCA())) {
               throw new AnnotatedException("End CRL only contains CA certificates.");
            }
         }

         if (var3.onlyContainsAttributeCerts()) {
            throw new AnnotatedException("onlyContainsAttributeCerts boolean is asserted.");
         }
      }

   }

   protected static void processCRLB1(DistributionPoint var0, Object var1, X509CRL var2) throws AnnotatedException {
      ASN1Primitive var3 = CertPathValidatorUtilities.getExtensionValue(var2, ISSUING_DISTRIBUTION_POINT);
      boolean var4 = false;
      if (var3 != null && IssuingDistributionPoint.getInstance(var3).isIndirectCRL()) {
         var4 = true;
      }

      byte[] var5 = CertPathValidatorUtilities.getIssuerPrincipal(var2).getEncoded();
      boolean var6 = false;
      if (var0.getCRLIssuer() != null) {
         GeneralName[] var7 = var0.getCRLIssuer().getNames();

         for(int var8 = 0; var8 < var7.length; ++var8) {
            if (var7[var8].getTagNo() == 4) {
               try {
                  if (Arrays.areEqual(var7[var8].getName().toASN1Primitive().getEncoded(), var5)) {
                     var6 = true;
                  }
               } catch (IOException var10) {
                  throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", var10);
               }
            }
         }

         if (var6 && !var4) {
            throw new AnnotatedException("Distribution point contains cRLIssuer field but CRL is not indirect.");
         }

         if (!var6) {
            throw new AnnotatedException("CRL issuer of CRL does not match CRL issuer of distribution point.");
         }
      } else if (CertPathValidatorUtilities.getIssuerPrincipal(var2).equals(CertPathValidatorUtilities.getEncodedIssuerPrincipal(var1))) {
         var6 = true;
      }

      if (!var6) {
         throw new AnnotatedException("Cannot find matching CRL issuer for certificate.");
      }
   }

   protected static ReasonsMask processCRLD(X509CRL var0, DistributionPoint var1) throws AnnotatedException {
      IssuingDistributionPoint var2 = null;

      try {
         var2 = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var0, ISSUING_DISTRIBUTION_POINT));
      } catch (Exception var4) {
         throw new AnnotatedException("Issuing distribution point extension could not be decoded.", var4);
      }

      if (var2 != null && var2.getOnlySomeReasons() != null && var1.getReasons() != null) {
         return (new ReasonsMask(var1.getReasons())).intersect(new ReasonsMask(var2.getOnlySomeReasons()));
      } else {
         return (var2 == null || var2.getOnlySomeReasons() == null) && var1.getReasons() == null ? ReasonsMask.allReasons : (var1.getReasons() == null ? ReasonsMask.allReasons : new ReasonsMask(var1.getReasons())).intersect(var2 == null ? ReasonsMask.allReasons : new ReasonsMask(var2.getOnlySomeReasons()));
      }
   }

   protected static Set processCRLF(X509CRL var0, Object var1, X509Certificate var2, PublicKey var3, ExtendedPKIXParameters var4, List var5) throws AnnotatedException {
      X509CertStoreSelector var6 = new X509CertStoreSelector();

      try {
         byte[] var7 = CertPathValidatorUtilities.getIssuerPrincipal(var0).getEncoded();
         var6.setSubject(var7);
      } catch (IOException var20) {
         throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate for CRL could not be set.", var20);
      }

      Collection var21;
      try {
         var21 = CertPathValidatorUtilities.findCertificates(var6, var4.getStores());
         var21.addAll(CertPathValidatorUtilities.findCertificates(var6, var4.getAdditionalStores()));
         var21.addAll(CertPathValidatorUtilities.findCertificates(var6, var4.getCertStores()));
      } catch (AnnotatedException var19) {
         throw new AnnotatedException("Issuer certificate for CRL cannot be searched.", var19);
      }

      var21.add(var2);
      Iterator var8 = var21.iterator();
      ArrayList var9 = new ArrayList();
      ArrayList var10 = new ArrayList();

      while(var8.hasNext()) {
         X509Certificate var11 = (X509Certificate)var8.next();
         if (var11.equals(var2)) {
            var9.add(var11);
            var10.add(var3);
         } else {
            try {
               CertPathBuilder var12 = CertPathBuilder.getInstance("PKIX", BouncyCastleProvider.PROVIDER_NAME);
               var6 = new X509CertStoreSelector();
               var6.setCertificate(var11);
               ExtendedPKIXParameters var13 = (ExtendedPKIXParameters)var4.clone();
               var13.setTargetCertConstraints(var6);
               ExtendedPKIXBuilderParameters var14 = (ExtendedPKIXBuilderParameters)ExtendedPKIXBuilderParameters.getInstance(var13);
               if (var5.contains(var11)) {
                  var14.setRevocationEnabled(false);
               } else {
                  var14.setRevocationEnabled(true);
               }

               List var15 = var12.build(var14).getCertPath().getCertificates();
               var9.add(var11);
               var10.add(CertPathValidatorUtilities.getNextWorkingKey(var15, 0));
            } catch (CertPathBuilderException var16) {
               throw new AnnotatedException("Internal error.", var16);
            } catch (CertPathValidatorException var17) {
               throw new AnnotatedException("Public key of issuer certificate of CRL could not be retrieved.", var17);
            } catch (Exception var18) {
               throw new RuntimeException(var18.getMessage());
            }
         }
      }

      HashSet var22 = new HashSet();
      AnnotatedException var23 = null;

      for(int var24 = 0; var24 < var9.size(); ++var24) {
         X509Certificate var25 = (X509Certificate)var9.get(var24);
         boolean[] var26 = var25.getKeyUsage();
         if (var26 == null || var26.length >= 7 && var26[6]) {
            var22.add(var10.get(var24));
         } else {
            var23 = new AnnotatedException("Issuer certificate key usage extension does not permit CRL signing.");
         }
      }

      if (var22.isEmpty() && var23 == null) {
         throw new AnnotatedException("Cannot find a valid issuer certificate.");
      } else if (var22.isEmpty() && var23 != null) {
         throw var23;
      } else {
         return var22;
      }
   }

   protected static PublicKey processCRLG(X509CRL var0, Set var1) throws AnnotatedException {
      Exception var2 = null;
      Iterator var3 = var1.iterator();

      while(var3.hasNext()) {
         PublicKey var4 = (PublicKey)var3.next();

         try {
            var0.verify(var4);
            return var4;
         } catch (Exception var6) {
            var2 = var6;
         }
      }

      throw new AnnotatedException("Cannot verify CRL.", var2);
   }

   protected static X509CRL processCRLH(Set var0, PublicKey var1) throws AnnotatedException {
      Exception var2 = null;
      Iterator var3 = var0.iterator();

      while(var3.hasNext()) {
         X509CRL var4 = (X509CRL)var3.next();

         try {
            var4.verify(var1);
            return var4;
         } catch (Exception var6) {
            var2 = var6;
         }
      }

      if (var2 != null) {
         throw new AnnotatedException("Cannot verify delta CRL.", var2);
      } else {
         return null;
      }
   }

   protected static Set processCRLA1i(Date var0, ExtendedPKIXParameters var1, X509Certificate var2, X509CRL var3) throws AnnotatedException {
      HashSet var4 = new HashSet();
      if (var1.isUseDeltasEnabled()) {
         CRLDistPoint var5 = null;

         try {
            var5 = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var2, FRESHEST_CRL));
         } catch (AnnotatedException var10) {
            throw new AnnotatedException("Freshest CRL extension could not be decoded from certificate.", var10);
         }

         if (var5 == null) {
            try {
               var5 = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var3, FRESHEST_CRL));
            } catch (AnnotatedException var9) {
               throw new AnnotatedException("Freshest CRL extension could not be decoded from CRL.", var9);
            }
         }

         if (var5 != null) {
            try {
               CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(var5, var1);
            } catch (AnnotatedException var8) {
               throw new AnnotatedException("No new delta CRL locations could be added from Freshest CRL extension.", var8);
            }

            try {
               var4.addAll(CertPathValidatorUtilities.getDeltaCRLs(var0, var1, var3));
            } catch (AnnotatedException var7) {
               throw new AnnotatedException("Exception obtaining delta CRLs.", var7);
            }
         }
      }

      return var4;
   }

   protected static Set[] processCRLA1ii(Date var0, ExtendedPKIXParameters var1, X509Certificate var2, X509CRL var3) throws AnnotatedException {
      HashSet var4 = new HashSet();
      X509CRLStoreSelector var5 = new X509CRLStoreSelector();
      var5.setCertificateChecking(var2);

      try {
         var5.addIssuerName(var3.getIssuerX500Principal().getEncoded());
      } catch (IOException var9) {
         throw new AnnotatedException("Cannot extract issuer from CRL." + var9, var9);
      }

      var5.setCompleteCRLEnabled(true);
      Set var6 = CRL_UTIL.findCRLs(var5, var1, var0);
      if (var1.isUseDeltasEnabled()) {
         try {
            var4.addAll(CertPathValidatorUtilities.getDeltaCRLs(var0, var1, var3));
         } catch (AnnotatedException var8) {
            throw new AnnotatedException("Exception obtaining delta CRLs.", var8);
         }
      }

      return new Set[]{var6, var4};
   }

   protected static void processCRLC(X509CRL var0, X509CRL var1, ExtendedPKIXParameters var2) throws AnnotatedException {
      if (var0 != null) {
         IssuingDistributionPoint var3 = null;

         try {
            var3 = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var1, ISSUING_DISTRIBUTION_POINT));
         } catch (Exception var12) {
            throw new AnnotatedException("Issuing distribution point extension could not be decoded.", var12);
         }

         if (var2.isUseDeltasEnabled()) {
            if (!var0.getIssuerX500Principal().equals(var1.getIssuerX500Principal())) {
               throw new AnnotatedException("Complete CRL issuer does not match delta CRL issuer.");
            }

            IssuingDistributionPoint var4 = null;

            try {
               var4 = IssuingDistributionPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var0, ISSUING_DISTRIBUTION_POINT));
            } catch (Exception var11) {
               throw new AnnotatedException("Issuing distribution point extension from delta CRL could not be decoded.", var11);
            }

            boolean var5 = false;
            if (var3 == null) {
               if (var4 == null) {
                  var5 = true;
               }
            } else if (var3.equals(var4)) {
               var5 = true;
            }

            if (!var5) {
               throw new AnnotatedException("Issuing distribution point extension from delta CRL and complete CRL does not match.");
            }

            ASN1Primitive var6 = null;

            try {
               var6 = CertPathValidatorUtilities.getExtensionValue(var1, AUTHORITY_KEY_IDENTIFIER);
            } catch (AnnotatedException var10) {
               throw new AnnotatedException("Authority key identifier extension could not be extracted from complete CRL.", var10);
            }

            ASN1Primitive var7 = null;

            try {
               var7 = CertPathValidatorUtilities.getExtensionValue(var0, AUTHORITY_KEY_IDENTIFIER);
            } catch (AnnotatedException var9) {
               throw new AnnotatedException("Authority key identifier extension could not be extracted from delta CRL.", var9);
            }

            if (var6 == null) {
               throw new AnnotatedException("CRL authority key identifier is null.");
            }

            if (var7 == null) {
               throw new AnnotatedException("Delta CRL authority key identifier is null.");
            }

            if (!var6.equals(var7)) {
               throw new AnnotatedException("Delta CRL authority key identifier does not match complete CRL authority key identifier.");
            }
         }

      }
   }

   protected static void processCRLI(Date var0, X509CRL var1, Object var2, CertStatus var3, ExtendedPKIXParameters var4) throws AnnotatedException {
      if (var4.isUseDeltasEnabled() && var1 != null) {
         CertPathValidatorUtilities.getCertStatus(var0, var1, var2, var3);
      }

   }

   protected static void processCRLJ(Date var0, X509CRL var1, Object var2, CertStatus var3) throws AnnotatedException {
      if (var3.getCertStatus() == 11) {
         CertPathValidatorUtilities.getCertStatus(var0, var1, var2, var3);
      }

   }

   protected static PKIXPolicyNode prepareCertB(CertPath var0, int var1, List[] var2, PKIXPolicyNode var3, int var4) throws CertPathValidatorException {
      List var5 = var0.getCertificates();
      X509Certificate var6 = (X509Certificate)var5.get(var1);
      int var7 = var5.size();
      int var8 = var7 - var1;
      ASN1Sequence var9 = null;

      try {
         var9 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var6, POLICY_MAPPINGS));
      } catch (AnnotatedException var28) {
         throw new ExtCertPathValidatorException("Policy mappings extension could not be decoded.", var28, var0, var1);
      }

      PKIXPolicyNode var10 = var3;
      if (var9 != null) {
         ASN1Sequence var11 = var9;
         HashMap var12 = new HashMap();
         HashSet var13 = new HashSet();

         for(int var14 = 0; var14 < var11.size(); ++var14) {
            ASN1Sequence var15 = (ASN1Sequence)var11.getObjectAt(var14);
            String var16 = ((DERObjectIdentifier)var15.getObjectAt(0)).getId();
            String var17 = ((DERObjectIdentifier)var15.getObjectAt(1)).getId();
            if (!var12.containsKey(var16)) {
               HashSet var18 = new HashSet();
               var18.add(var17);
               var12.put(var16, var18);
               var13.add(var16);
            } else {
               Set var35 = (Set)var12.get(var16);
               var35.add(var17);
            }
         }

         Iterator var29 = var13.iterator();

         while(true) {
            while(true) {
               List var20;
               PKIXPolicyNode var22;
               String var30;
               boolean var32;
               Iterator var34;
               PKIXPolicyNode var36;
               label118:
               do {
                  label107:
                  while(var29.hasNext()) {
                     var30 = (String)var29.next();
                     if (var4 > 0) {
                        var32 = false;
                        var34 = var2[var8].iterator();

                        while(var34.hasNext()) {
                           var36 = (PKIXPolicyNode)var34.next();
                           if (var36.getValidPolicy().equals(var30)) {
                              var32 = true;
                              var36.expectedPolicies = (Set)var12.get(var30);
                              continue label118;
                           }
                        }
                        continue label118;
                     }

                     if (var4 <= 0) {
                        Iterator var31 = var2[var8].iterator();

                        while(true) {
                           PKIXPolicyNode var33;
                           do {
                              if (!var31.hasNext()) {
                                 continue label107;
                              }

                              var33 = (PKIXPolicyNode)var31.next();
                           } while(!var33.getValidPolicy().equals(var30));

                           var36 = (PKIXPolicyNode)var33.getParent();
                           var36.removeChild(var33);
                           var31.remove();

                           for(int var19 = var8 - 1; var19 >= 0; --var19) {
                              var20 = var2[var19];

                              for(int var21 = 0; var21 < var20.size(); ++var21) {
                                 var22 = (PKIXPolicyNode)var20.get(var21);
                                 if (!var22.hasChildren()) {
                                    var10 = CertPathValidatorUtilities.removePolicyNode(var10, var2, var22);
                                    if (var10 == null) {
                                       break;
                                    }
                                 }
                              }
                           }
                        }
                     }
                  }

                  return var10;
               } while(var32);

               var34 = var2[var8].iterator();

               while(var34.hasNext()) {
                  var36 = (PKIXPolicyNode)var34.next();
                  if ("2.5.29.32.0".equals(var36.getValidPolicy())) {
                     Set var37 = null;
                     var20 = null;

                     ASN1Sequence var38;
                     try {
                        var38 = (ASN1Sequence)CertPathValidatorUtilities.getExtensionValue(var6, CERTIFICATE_POLICIES);
                     } catch (AnnotatedException var27) {
                        throw new ExtCertPathValidatorException("Certificate policies extension could not be decoded.", var27, var0, var1);
                     }

                     Enumeration var39 = var38.getObjects();

                     while(var39.hasMoreElements()) {
                        var22 = null;

                        PolicyInformation var40;
                        try {
                           var40 = PolicyInformation.getInstance(var39.nextElement());
                        } catch (Exception var26) {
                           throw new CertPathValidatorException("Policy information could not be decoded.", var26, var0, var1);
                        }

                        if ("2.5.29.32.0".equals(var40.getPolicyIdentifier().getId())) {
                           try {
                              var37 = CertPathValidatorUtilities.getQualifierSet(var40.getPolicyQualifiers());
                              break;
                           } catch (CertPathValidatorException var25) {
                              throw new ExtCertPathValidatorException("Policy qualifier info set could not be decoded.", var25, var0, var1);
                           }
                        }
                     }

                     boolean var41 = false;
                     if (var6.getCriticalExtensionOIDs() != null) {
                        var41 = var6.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
                     }

                     PKIXPolicyNode var23 = (PKIXPolicyNode)var36.getParent();
                     if ("2.5.29.32.0".equals(var23.getValidPolicy())) {
                        PKIXPolicyNode var24 = new PKIXPolicyNode(new ArrayList(), var8, (Set)var12.get(var30), var23, var37, var30, var41);
                        var23.addChild(var24);
                        var2[var8].add(var24);
                     }
                     break;
                  }
               }
            }
         }
      } else {
         return var10;
      }
   }

   protected static void prepareNextCertA(CertPath var0, int var1) throws CertPathValidatorException {
      List var2 = var0.getCertificates();
      X509Certificate var3 = (X509Certificate)var2.get(var1);
      ASN1Sequence var4 = null;

      try {
         var4 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var3, POLICY_MAPPINGS));
      } catch (AnnotatedException var11) {
         throw new ExtCertPathValidatorException("Policy mappings extension could not be decoded.", var11, var0, var1);
      }

      if (var4 != null) {
         ASN1Sequence var5 = var4;

         for(int var6 = 0; var6 < var5.size(); ++var6) {
            ASN1ObjectIdentifier var7 = null;
            ASN1ObjectIdentifier var8 = null;

            try {
               ASN1Sequence var9 = DERSequence.getInstance(var5.getObjectAt(var6));
               var7 = DERObjectIdentifier.getInstance(var9.getObjectAt(0));
               var8 = DERObjectIdentifier.getInstance(var9.getObjectAt(1));
            } catch (Exception var10) {
               throw new ExtCertPathValidatorException("Policy mappings extension contents could not be decoded.", var10, var0, var1);
            }

            if ("2.5.29.32.0".equals(var7.getId())) {
               throw new CertPathValidatorException("IssuerDomainPolicy is anyPolicy", (Throwable)null, var0, var1);
            }

            if ("2.5.29.32.0".equals(var8.getId())) {
               throw new CertPathValidatorException("SubjectDomainPolicy is anyPolicy,", (Throwable)null, var0, var1);
            }
         }
      }

   }

   protected static void processCertF(CertPath var0, int var1, PKIXPolicyNode var2, int var3) throws CertPathValidatorException {
      if (var3 <= 0 && var2 == null) {
         throw new ExtCertPathValidatorException("No valid policy tree found when one expected.", (Throwable)null, var0, var1);
      }
   }

   protected static PKIXPolicyNode processCertE(CertPath var0, int var1, PKIXPolicyNode var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      ASN1Sequence var5 = null;

      try {
         var5 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, CERTIFICATE_POLICIES));
      } catch (AnnotatedException var7) {
         throw new ExtCertPathValidatorException("Could not read certificate policies extension from certificate.", var7, var0, var1);
      }

      if (var5 == null) {
         var2 = null;
      }

      return var2;
   }

   protected static void processCertBC(CertPath var0, int var1, PKIXNameConstraintValidator var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      int var5 = var3.size();
      int var6 = var5 - var1;
      if (!CertPathValidatorUtilities.isSelfIssued(var4) || var6 >= var5) {
         X500Principal var7 = CertPathValidatorUtilities.getSubjectPrincipal(var4);
         ASN1InputStream var8 = new ASN1InputStream(var7.getEncoded());

         ASN1Sequence var9;
         try {
            var9 = DERSequence.getInstance(var8.readObject());
         } catch (Exception var21) {
            throw new CertPathValidatorException("Exception extracting subject name when checking subtrees.", var21, var0, var1);
         }

         try {
            var2.checkPermittedDN(var9);
            var2.checkExcludedDN(var9);
         } catch (PKIXNameConstraintValidatorException var20) {
            throw new CertPathValidatorException("Subtree check for certificate subject failed.", var20, var0, var1);
         }

         GeneralNames var10 = null;

         try {
            var10 = GeneralNames.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, SUBJECT_ALTERNATIVE_NAME));
         } catch (Exception var19) {
            throw new CertPathValidatorException("Subject alternative name extension could not be decoded.", var19, var0, var1);
         }

         Vector var11 = (new X509Name(var9)).getValues(X509Name.EmailAddress);
         Enumeration var12 = var11.elements();

         while(var12.hasMoreElements()) {
            String var13 = (String)var12.nextElement();
            GeneralName var14 = new GeneralName(1, var13);

            try {
               var2.checkPermitted(var14);
               var2.checkExcluded(var14);
            } catch (PKIXNameConstraintValidatorException var18) {
               throw new CertPathValidatorException("Subtree check for certificate subject alternative email failed.", var18, var0, var1);
            }
         }

         if (var10 != null) {
            var12 = null;

            GeneralName[] var22;
            try {
               var22 = var10.getNames();
            } catch (Exception var17) {
               throw new CertPathValidatorException("Subject alternative name contents could not be decoded.", var17, var0, var1);
            }

            for(int var23 = 0; var23 < var22.length; ++var23) {
               try {
                  var2.checkPermitted(var22[var23]);
                  var2.checkExcluded(var22[var23]);
               } catch (PKIXNameConstraintValidatorException var16) {
                  throw new CertPathValidatorException("Subtree check for certificate subject alternative name failed.", var16, var0, var1);
               }
            }
         }
      }

   }

   protected static PKIXPolicyNode processCertD(CertPath var0, int var1, Set var2, PKIXPolicyNode var3, List[] var4, int var5) throws CertPathValidatorException {
      List var6 = var0.getCertificates();
      X509Certificate var7 = (X509Certificate)var6.get(var1);
      int var8 = var6.size();
      int var9 = var8 - var1;
      ASN1Sequence var10 = null;

      try {
         var10 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var7, CERTIFICATE_POLICIES));
      } catch (AnnotatedException var26) {
         throw new ExtCertPathValidatorException("Could not read certificate policies extension from certificate.", var26, var0, var1);
      }

      if (var10 != null && var3 != null) {
         Enumeration var11 = var10.getObjects();
         HashSet var12 = new HashSet();

         PolicyInformation var13;
         while(var11.hasMoreElements()) {
            var13 = PolicyInformation.getInstance(var11.nextElement());
            ASN1ObjectIdentifier var14 = var13.getPolicyIdentifier();
            var12.add(var14.getId());
            if (!"2.5.29.32.0".equals(var14.getId())) {
               Set var15 = null;

               try {
                  var15 = CertPathValidatorUtilities.getQualifierSet(var13.getPolicyQualifiers());
               } catch (CertPathValidatorException var25) {
                  throw new ExtCertPathValidatorException("Policy qualifier info set could not be build.", var25, var0, var1);
               }

               boolean var16 = CertPathValidatorUtilities.processCertD1i(var9, var4, var14, var15);
               if (!var16) {
                  CertPathValidatorUtilities.processCertD1ii(var9, var4, var14, var15);
               }
            }
         }

         if (!var2.isEmpty() && !var2.contains("2.5.29.32.0")) {
            Iterator var27 = var2.iterator();
            HashSet var29 = new HashSet();

            while(var27.hasNext()) {
               Object var32 = var27.next();
               if (var12.contains(var32)) {
                  var29.add(var32);
               }
            }

            var2.clear();
            var2.addAll(var29);
         } else {
            var2.clear();
            var2.addAll(var12);
         }

         PKIXPolicyNode var17;
         Set var30;
         List var33;
         int var34;
         if (var5 > 0 || var9 < var8 && CertPathValidatorUtilities.isSelfIssued(var7)) {
            var11 = var10.getObjects();

            label125:
            while(var11.hasMoreElements()) {
               var13 = PolicyInformation.getInstance(var11.nextElement());
               if ("2.5.29.32.0".equals(var13.getPolicyIdentifier().getId())) {
                  var30 = CertPathValidatorUtilities.getQualifierSet(var13.getPolicyQualifiers());
                  var33 = var4[var9 - 1];
                  var34 = 0;

                  label119:
                  while(true) {
                     if (var34 >= var33.size()) {
                        break label125;
                     }

                     var17 = (PKIXPolicyNode)var33.get(var34);
                     Iterator var18 = var17.getExpectedPolicies().iterator();

                     while(true) {
                        String var20;
                        while(true) {
                           if (!var18.hasNext()) {
                              ++var34;
                              continue label119;
                           }

                           Object var19 = var18.next();
                           if (var19 instanceof String) {
                              var20 = (String)var19;
                              break;
                           }

                           if (var19 instanceof DERObjectIdentifier) {
                              var20 = ((DERObjectIdentifier)var19).getId();
                              break;
                           }
                        }

                        boolean var21 = false;
                        Iterator var22 = var17.getChildren();

                        while(var22.hasNext()) {
                           PKIXPolicyNode var23 = (PKIXPolicyNode)var22.next();
                           if (var20.equals(var23.getValidPolicy())) {
                              var21 = true;
                           }
                        }

                        if (!var21) {
                           HashSet var39 = new HashSet();
                           var39.add(var20);
                           PKIXPolicyNode var24 = new PKIXPolicyNode(new ArrayList(), var9, var39, var17, var30, var20, false);
                           var17.addChild(var24);
                           var4[var9].add(var24);
                        }
                     }
                  }
               }
            }
         }

         PKIXPolicyNode var28 = var3;

         for(int var31 = var9 - 1; var31 >= 0; --var31) {
            var33 = var4[var31];

            for(var34 = 0; var34 < var33.size(); ++var34) {
               var17 = (PKIXPolicyNode)var33.get(var34);
               if (!var17.hasChildren()) {
                  var28 = CertPathValidatorUtilities.removePolicyNode(var28, var4, var17);
                  if (var28 == null) {
                     break;
                  }
               }
            }
         }

         var30 = var7.getCriticalExtensionOIDs();
         if (var30 != null) {
            boolean var35 = var30.contains(CERTIFICATE_POLICIES);
            List var36 = var4[var9];

            for(int var37 = 0; var37 < var36.size(); ++var37) {
               PKIXPolicyNode var38 = (PKIXPolicyNode)var36.get(var37);
               var38.setCritical(var35);
            }
         }

         return var28;
      } else {
         return null;
      }
   }

   protected static void processCertA(CertPath var0, ExtendedPKIXParameters var1, int var2, PublicKey var3, boolean var4, X500Principal var5, X509Certificate var6) throws ExtCertPathValidatorException {
      List var7 = var0.getCertificates();
      X509Certificate var8 = (X509Certificate)var7.get(var2);
      if (!var4) {
         try {
            CertPathValidatorUtilities.verifyX509Certificate(var8, var3, var1.getSigProvider());
         } catch (GeneralSecurityException var14) {
            throw new ExtCertPathValidatorException("Could not validate certificate signature.", var14, var0, var2);
         }
      }

      try {
         var8.checkValidity(CertPathValidatorUtilities.getValidCertDateFromValidityModel(var1, var0, var2));
      } catch (CertificateExpiredException var11) {
         throw new ExtCertPathValidatorException("Could not validate certificate: " + var11.getMessage(), var11, var0, var2);
      } catch (CertificateNotYetValidException var12) {
         throw new ExtCertPathValidatorException("Could not validate certificate: " + var12.getMessage(), var12, var0, var2);
      } catch (AnnotatedException var13) {
         throw new ExtCertPathValidatorException("Could not validate time of certificate.", var13, var0, var2);
      }

      if (var1.isRevocationEnabled()) {
         try {
            checkCRLs(var1, var8, CertPathValidatorUtilities.getValidCertDateFromValidityModel(var1, var0, var2), var6, var3, var7);
         } catch (AnnotatedException var15) {
            Object var10 = var15;
            if (var15.getCause() != null) {
               var10 = var15.getCause();
            }

            throw new ExtCertPathValidatorException(var15.getMessage(), (Throwable)var10, var0, var2);
         }
      }

      if (!CertPathValidatorUtilities.getEncodedIssuerPrincipal(var8).equals(var5)) {
         throw new ExtCertPathValidatorException("IssuerName(" + CertPathValidatorUtilities.getEncodedIssuerPrincipal(var8) + ") does not match SubjectName(" + var5 + ") of signing certificate.", (Throwable)null, var0, var2);
      }
   }

   protected static int prepareNextCertI1(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      ASN1Sequence var5 = null;

      try {
         var5 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, POLICY_CONSTRAINTS));
      } catch (Exception var9) {
         throw new ExtCertPathValidatorException("Policy constraints extension cannot be decoded.", var9, var0, var1);
      }

      if (var5 != null) {
         Enumeration var7 = var5.getObjects();

         while(var7.hasMoreElements()) {
            try {
               ASN1TaggedObject var8 = ASN1TaggedObject.getInstance(var7.nextElement());
               if (var8.getTagNo() == 0) {
                  int var6 = DERInteger.getInstance(var8, false).getValue().intValue();
                  if (var6 < var2) {
                     return var6;
                  }
                  break;
               }
            } catch (IllegalArgumentException var10) {
               throw new ExtCertPathValidatorException("Policy constraints extension contents cannot be decoded.", var10, var0, var1);
            }
         }
      }

      return var2;
   }

   protected static int prepareNextCertI2(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      ASN1Sequence var5 = null;

      try {
         var5 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, POLICY_CONSTRAINTS));
      } catch (Exception var9) {
         throw new ExtCertPathValidatorException("Policy constraints extension cannot be decoded.", var9, var0, var1);
      }

      if (var5 != null) {
         Enumeration var7 = var5.getObjects();

         while(var7.hasMoreElements()) {
            try {
               ASN1TaggedObject var8 = ASN1TaggedObject.getInstance(var7.nextElement());
               if (var8.getTagNo() == 1) {
                  int var6 = DERInteger.getInstance(var8, false).getValue().intValue();
                  if (var6 < var2) {
                     return var6;
                  }
                  break;
               }
            } catch (IllegalArgumentException var10) {
               throw new ExtCertPathValidatorException("Policy constraints extension contents cannot be decoded.", var10, var0, var1);
            }
         }
      }

      return var2;
   }

   protected static void prepareNextCertG(CertPath var0, int var1, PKIXNameConstraintValidator var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      NameConstraints var5 = null;

      try {
         ASN1Sequence var6 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, NAME_CONSTRAINTS));
         if (var6 != null) {
            var5 = NameConstraints.getInstance(var6);
         }
      } catch (Exception var12) {
         throw new ExtCertPathValidatorException("Name constraints extension could not be decoded.", var12, var0, var1);
      }

      if (var5 != null) {
         GeneralSubtree[] var13 = var5.getPermittedSubtrees();
         if (var13 != null) {
            try {
               var2.intersectPermittedSubtree(var13);
            } catch (Exception var11) {
               throw new ExtCertPathValidatorException("Permitted subtrees cannot be build from name constraints extension.", var11, var0, var1);
            }
         }

         GeneralSubtree[] var7 = var5.getExcludedSubtrees();
         if (var7 != null) {
            for(int var8 = 0; var8 != var7.length; ++var8) {
               try {
                  var2.addExcludedSubtree(var7[var8]);
               } catch (Exception var10) {
                  throw new ExtCertPathValidatorException("Excluded subtrees cannot be build from name constraints extension.", var10, var0, var1);
               }
            }
         }
      }

   }

   private static void checkCRL(DistributionPoint var0, ExtendedPKIXParameters var1, X509Certificate var2, Date var3, X509Certificate var4, PublicKey var5, CertStatus var6, ReasonsMask var7, List var8) throws AnnotatedException {
      Date var9 = new Date(System.currentTimeMillis());
      if (var3.getTime() > var9.getTime()) {
         throw new AnnotatedException("Validation time is in future.");
      } else {
         Set var10 = CertPathValidatorUtilities.getCompleteCRLs(var0, var2, var9, var1);
         boolean var11 = false;
         AnnotatedException var12 = null;
         Iterator var13 = var10.iterator();

         while(var13.hasNext() && var6.getCertStatus() == 11 && !var7.isAllReasons()) {
            try {
               X509CRL var14 = (X509CRL)var13.next();
               ReasonsMask var15 = processCRLD(var14, var0);
               if (var15.hasNewReasons(var7)) {
                  Set var16 = processCRLF(var14, var2, var4, var5, var1, var8);
                  PublicKey var17 = processCRLG(var14, var16);
                  X509CRL var18 = null;
                  Set var19;
                  if (var1.isUseDeltasEnabled()) {
                     var19 = CertPathValidatorUtilities.getDeltaCRLs(var9, var1, var14);
                     var18 = processCRLH(var19, var17);
                  }

                  if (var1.getValidityModel() != 1 && var2.getNotAfter().getTime() < var14.getThisUpdate().getTime()) {
                     throw new AnnotatedException("No valid CRL for current time found.");
                  }

                  processCRLB1(var0, var2, var14);
                  processCRLB2(var0, var2, var14);
                  processCRLC(var18, var14, var1);
                  processCRLI(var3, var18, var2, var6, var1);
                  processCRLJ(var3, var14, var2, var6);
                  if (var6.getCertStatus() == 8) {
                     var6.setCertStatus(11);
                  }

                  var7.addReasons(var15);
                  var19 = var14.getCriticalExtensionOIDs();
                  HashSet var21;
                  if (var19 != null) {
                     var21 = new HashSet(var19);
                     var21.remove(X509Extensions.IssuingDistributionPoint.getId());
                     var21.remove(X509Extensions.DeltaCRLIndicator.getId());
                     if (!var21.isEmpty()) {
                        throw new AnnotatedException("CRL contains unsupported critical extensions.");
                     }
                  }

                  if (var18 != null) {
                     var19 = var18.getCriticalExtensionOIDs();
                     if (var19 != null) {
                        var21 = new HashSet(var19);
                        var21.remove(X509Extensions.IssuingDistributionPoint.getId());
                        var21.remove(X509Extensions.DeltaCRLIndicator.getId());
                        if (!var21.isEmpty()) {
                           throw new AnnotatedException("Delta CRL contains unsupported critical extension.");
                        }
                     }
                  }

                  var11 = true;
               }
            } catch (AnnotatedException var20) {
               var12 = var20;
            }
         }

         if (!var11) {
            throw var12;
         }
      }
   }

   protected static void checkCRLs(ExtendedPKIXParameters var0, X509Certificate var1, Date var2, X509Certificate var3, PublicKey var4, List var5) throws AnnotatedException {
      AnnotatedException var6 = null;
      CRLDistPoint var7 = null;

      try {
         var7 = CRLDistPoint.getInstance(CertPathValidatorUtilities.getExtensionValue(var1, CRL_DISTRIBUTION_POINTS));
      } catch (Exception var20) {
         throw new AnnotatedException("CRL distribution point extension could not be read.", var20);
      }

      try {
         CertPathValidatorUtilities.addAdditionalStoresFromCRLDistributionPoint(var7, var0);
      } catch (AnnotatedException var19) {
         throw new AnnotatedException("No additional CRL locations could be decoded from CRL distribution point extension.", var19);
      }

      CertStatus var8 = new CertStatus();
      ReasonsMask var9 = new ReasonsMask();
      boolean var10 = false;
      DistributionPoint[] var11;
      ExtendedPKIXParameters var13;
      if (var7 != null) {
         var11 = null;

         try {
            var11 = var7.getDistributionPoints();
         } catch (Exception var18) {
            throw new AnnotatedException("Distribution points could not be read.", var18);
         }

         if (var11 != null) {
            for(int var12 = 0; var12 < var11.length && var8.getCertStatus() == 11 && !var9.isAllReasons(); ++var12) {
               var13 = (ExtendedPKIXParameters)var0.clone();

               try {
                  checkCRL(var11[var12], var13, var1, var2, var3, var4, var8, var9, var5);
                  var10 = true;
               } catch (AnnotatedException var17) {
                  var6 = var17;
               }
            }
         }
      }

      if (var8.getCertStatus() == 11 && !var9.isAllReasons()) {
         try {
            var11 = null;

            ASN1Primitive var21;
            try {
               var21 = (new ASN1InputStream(CertPathValidatorUtilities.getEncodedIssuerPrincipal(var1).getEncoded())).readObject();
            } catch (Exception var15) {
               throw new AnnotatedException("Issuer from certificate for CRL could not be reencoded.", var15);
            }

            DistributionPoint var23 = new DistributionPoint(new DistributionPointName(0, new GeneralNames(new GeneralName(4, var21))), (ReasonFlags)null, (GeneralNames)null);
            var13 = (ExtendedPKIXParameters)var0.clone();
            checkCRL(var23, var13, var1, var2, var3, var4, var8, var9, var5);
            var10 = true;
         } catch (AnnotatedException var16) {
            var6 = var16;
         }
      }

      if (!var10) {
         if (var6 instanceof AnnotatedException) {
            throw var6;
         } else {
            throw new AnnotatedException("No valid CRL found.", var6);
         }
      } else if (var8.getCertStatus() != 11) {
         String var22 = "Certificate revocation after " + var8.getRevocationDate();
         var22 = var22 + ", reason: " + crlReasons[var8.getCertStatus()];
         throw new AnnotatedException(var22);
      } else {
         if (!var9.isAllReasons() && var8.getCertStatus() == 11) {
            var8.setCertStatus(12);
         }

         if (var8.getCertStatus() == 12) {
            throw new AnnotatedException("Certificate status could not be determined.");
         }
      }
   }

   protected static int prepareNextCertJ(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      ASN1Integer var5 = null;

      try {
         var5 = DERInteger.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, INHIBIT_ANY_POLICY));
      } catch (Exception var7) {
         throw new ExtCertPathValidatorException("Inhibit any-policy extension cannot be decoded.", var7, var0, var1);
      }

      if (var5 != null) {
         int var6 = var5.getValue().intValue();
         if (var6 < var2) {
            return var6;
         }
      }

      return var2;
   }

   protected static void prepareNextCertK(CertPath var0, int var1) throws CertPathValidatorException {
      List var2 = var0.getCertificates();
      X509Certificate var3 = (X509Certificate)var2.get(var1);
      BasicConstraints var4 = null;

      try {
         var4 = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue(var3, BASIC_CONSTRAINTS));
      } catch (Exception var6) {
         throw new ExtCertPathValidatorException("Basic constraints extension cannot be decoded.", var6, var0, var1);
      }

      if (var4 != null) {
         if (!var4.isCA()) {
            throw new CertPathValidatorException("Not a CA certificate");
         }
      } else {
         throw new CertPathValidatorException("Intermediate certificate lacks BasicConstraints");
      }
   }

   protected static int prepareNextCertL(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      if (!CertPathValidatorUtilities.isSelfIssued(var4)) {
         if (var2 <= 0) {
            throw new ExtCertPathValidatorException("Max path length not greater than zero", (Throwable)null, var0, var1);
         } else {
            return var2 - 1;
         }
      } else {
         return var2;
      }
   }

   protected static int prepareNextCertM(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      BasicConstraints var5 = null;

      try {
         var5 = BasicConstraints.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, BASIC_CONSTRAINTS));
      } catch (Exception var8) {
         throw new ExtCertPathValidatorException("Basic constraints extension cannot be decoded.", var8, var0, var1);
      }

      if (var5 != null) {
         BigInteger var6 = var5.getPathLenConstraint();
         if (var6 != null) {
            int var7 = var6.intValue();
            if (var7 < var2) {
               return var7;
            }
         }
      }

      return var2;
   }

   protected static void prepareNextCertN(CertPath var0, int var1) throws CertPathValidatorException {
      List var2 = var0.getCertificates();
      X509Certificate var3 = (X509Certificate)var2.get(var1);
      boolean[] var4 = var3.getKeyUsage();
      if (var4 != null && !var4[5]) {
         throw new ExtCertPathValidatorException("Issuer certificate keyusage extension is critical and does not permit key signing.", (Throwable)null, var0, var1);
      }
   }

   protected static void prepareNextCertO(CertPath var0, int var1, Set var2, List var3) throws CertPathValidatorException {
      List var4 = var0.getCertificates();
      X509Certificate var5 = (X509Certificate)var4.get(var1);
      Iterator var6 = var3.iterator();

      while(var6.hasNext()) {
         try {
            ((PKIXCertPathChecker)var6.next()).check(var5, var2);
         } catch (CertPathValidatorException var8) {
            throw new CertPathValidatorException(var8.getMessage(), var8.getCause(), var0, var1);
         }
      }

      if (!var2.isEmpty()) {
         throw new ExtCertPathValidatorException("Certificate has unsupported critical extension: " + var2, (Throwable)null, var0, var1);
      }
   }

   protected static int prepareNextCertH1(CertPath var0, int var1, int var2) {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      return !CertPathValidatorUtilities.isSelfIssued(var4) && var2 != 0 ? var2 - 1 : var2;
   }

   protected static int prepareNextCertH2(CertPath var0, int var1, int var2) {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      return !CertPathValidatorUtilities.isSelfIssued(var4) && var2 != 0 ? var2 - 1 : var2;
   }

   protected static int prepareNextCertH3(CertPath var0, int var1, int var2) {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      return !CertPathValidatorUtilities.isSelfIssued(var4) && var2 != 0 ? var2 - 1 : var2;
   }

   protected static int wrapupCertA(int var0, X509Certificate var1) {
      if (!CertPathValidatorUtilities.isSelfIssued(var1) && var0 != 0) {
         --var0;
      }

      return var0;
   }

   protected static int wrapupCertB(CertPath var0, int var1, int var2) throws CertPathValidatorException {
      List var3 = var0.getCertificates();
      X509Certificate var4 = (X509Certificate)var3.get(var1);
      ASN1Sequence var6 = null;

      try {
         var6 = DERSequence.getInstance(CertPathValidatorUtilities.getExtensionValue(var4, POLICY_CONSTRAINTS));
      } catch (AnnotatedException var11) {
         throw new ExtCertPathValidatorException("Policy constraints could not be decoded.", var11, var0, var1);
      }

      if (var6 != null) {
         Enumeration var7 = var6.getObjects();

         while(var7.hasMoreElements()) {
            ASN1TaggedObject var8 = (ASN1TaggedObject)var7.nextElement();
            switch(var8.getTagNo()) {
            case 0:
               int var5;
               try {
                  var5 = DERInteger.getInstance(var8, false).getValue().intValue();
               } catch (Exception var10) {
                  throw new ExtCertPathValidatorException("Policy constraints requireExplicitPolicy field could not be decoded.", var10, var0, var1);
               }

               if (var5 == 0) {
                  return 0;
               }
            }
         }
      }

      return var2;
   }

   protected static void wrapupCertF(CertPath var0, int var1, List var2, Set var3) throws CertPathValidatorException {
      List var4 = var0.getCertificates();
      X509Certificate var5 = (X509Certificate)var4.get(var1);
      Iterator var6 = var2.iterator();

      while(var6.hasNext()) {
         try {
            ((PKIXCertPathChecker)var6.next()).check(var5, var3);
         } catch (CertPathValidatorException var8) {
            throw new ExtCertPathValidatorException("Additional certificate path checker failed.", var8, var0, var1);
         }
      }

      if (!var3.isEmpty()) {
         throw new ExtCertPathValidatorException("Certificate has unsupported critical extension: " + var3, (Throwable)null, var0, var1);
      }
   }

   protected static PKIXPolicyNode wrapupCertG(CertPath var0, ExtendedPKIXParameters var1, Set var2, int var3, List[] var4, PKIXPolicyNode var5, Set var6) throws CertPathValidatorException {
      int var7 = var0.getCertificates().size();
      PKIXPolicyNode var8;
      if (var5 == null) {
         if (var1.isExplicitPolicyRequired()) {
            throw new ExtCertPathValidatorException("Explicit policy requested but none available.", (Throwable)null, var0, var3);
         }

         var8 = null;
      } else {
         HashSet var9;
         int var10;
         List var11;
         int var12;
         PKIXPolicyNode var13;
         Iterator var14;
         Iterator var16;
         PKIXPolicyNode var17;
         int var18;
         String var19;
         List var20;
         int var21;
         PKIXPolicyNode var22;
         if (CertPathValidatorUtilities.isAnyPolicy(var2)) {
            if (var1.isExplicitPolicyRequired()) {
               if (var6.isEmpty()) {
                  throw new ExtCertPathValidatorException("Explicit policy requested but none available.", (Throwable)null, var0, var3);
               }

               var9 = new HashSet();
               var10 = 0;

               label148:
               while(true) {
                  if (var10 >= var4.length) {
                     var16 = var9.iterator();

                     while(var16.hasNext()) {
                        var17 = (PKIXPolicyNode)var16.next();
                        var19 = var17.getValidPolicy();
                        var6.contains(var19);
                     }

                     if (var5 == null) {
                        break;
                     }

                     var18 = var7 - 1;

                     while(true) {
                        if (var18 < 0) {
                           break label148;
                        }

                        var20 = var4[var18];

                        for(var21 = 0; var21 < var20.size(); ++var21) {
                           var22 = (PKIXPolicyNode)var20.get(var21);
                           if (!var22.hasChildren()) {
                              var5 = CertPathValidatorUtilities.removePolicyNode(var5, var4, var22);
                           }
                        }

                        --var18;
                     }
                  }

                  var11 = var4[var10];

                  for(var12 = 0; var12 < var11.size(); ++var12) {
                     var13 = (PKIXPolicyNode)var11.get(var12);
                     if ("2.5.29.32.0".equals(var13.getValidPolicy())) {
                        var14 = var13.getChildren();

                        while(var14.hasNext()) {
                           var9.add(var14.next());
                        }
                     }
                  }

                  ++var10;
               }
            }

            var8 = var5;
         } else {
            var9 = new HashSet();

            for(var10 = 0; var10 < var4.length; ++var10) {
               var11 = var4[var10];

               for(var12 = 0; var12 < var11.size(); ++var12) {
                  var13 = (PKIXPolicyNode)var11.get(var12);
                  if ("2.5.29.32.0".equals(var13.getValidPolicy())) {
                     var14 = var13.getChildren();

                     while(var14.hasNext()) {
                        PKIXPolicyNode var15 = (PKIXPolicyNode)var14.next();
                        if (!"2.5.29.32.0".equals(var15.getValidPolicy())) {
                           var9.add(var15);
                        }
                     }
                  }
               }
            }

            var16 = var9.iterator();

            while(var16.hasNext()) {
               var17 = (PKIXPolicyNode)var16.next();
               var19 = var17.getValidPolicy();
               if (!var2.contains(var19)) {
                  var5 = CertPathValidatorUtilities.removePolicyNode(var5, var4, var17);
               }
            }

            if (var5 != null) {
               for(var18 = var7 - 1; var18 >= 0; --var18) {
                  var20 = var4[var18];

                  for(var21 = 0; var21 < var20.size(); ++var21) {
                     var22 = (PKIXPolicyNode)var20.get(var21);
                     if (!var22.hasChildren()) {
                        var5 = CertPathValidatorUtilities.removePolicyNode(var5, var4, var22);
                     }
                  }
               }
            }

            var8 = var5;
         }
      }

      return var8;
   }
}
