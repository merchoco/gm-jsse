package org.bc.jce.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.util.ASN1Dump;
import org.bc.asn1.x500.X500Name;
import org.bc.asn1.x509.CRLDistPoint;
import org.bc.asn1.x509.CRLNumber;
import org.bc.asn1.x509.CertificateList;
import org.bc.asn1.x509.Extension;
import org.bc.asn1.x509.Extensions;
import org.bc.asn1.x509.GeneralNames;
import org.bc.asn1.x509.IssuingDistributionPoint;
import org.bc.asn1.x509.TBSCertList;
import org.bc.jce.X509Principal;
import org.bc.util.encoders.Hex;

public class X509CRLObject extends X509CRL {
   private CertificateList c;
   private String sigAlgName;
   private byte[] sigAlgParams;
   private boolean isIndirect;

   static boolean isIndirectCRL(X509CRL var0) throws CRLException {
      try {
         byte[] var1 = var0.getExtensionValue(Extension.issuingDistributionPoint.getId());
         return var1 != null && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(var1).getOctets()).isIndirectCRL();
      } catch (Exception var2) {
         throw new ExtCRLException("Exception reading IssuingDistributionPoint", var2);
      }
   }

   public X509CRLObject(CertificateList var1) throws CRLException {
      this.c = var1;

      try {
         this.sigAlgName = X509SignatureUtil.getSignatureName(var1.getSignatureAlgorithm());
         if (var1.getSignatureAlgorithm().getParameters() != null) {
            this.sigAlgParams = var1.getSignatureAlgorithm().getParameters().toASN1Primitive().getEncoded("DER");
         } else {
            this.sigAlgParams = null;
         }

         this.isIndirect = isIndirectCRL(this);
      } catch (Exception var3) {
         throw new CRLException("CRL contents invalid: " + var3);
      }
   }

   public boolean hasUnsupportedCriticalExtension() {
      Set var1 = this.getCriticalExtensionOIDs();
      if (var1 == null) {
         return false;
      } else {
         var1.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
         var1.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
         return !var1.isEmpty();
      }
   }

   private Set getExtensionOIDs(boolean var1) {
      if (this.getVersion() == 2) {
         Extensions var2 = this.c.getTBSCertList().getExtensions();
         if (var2 != null) {
            HashSet var3 = new HashSet();
            Enumeration var4 = var2.oids();

            while(var4.hasMoreElements()) {
               ASN1ObjectIdentifier var5 = (ASN1ObjectIdentifier)var4.nextElement();
               Extension var6 = var2.getExtension(var5);
               if (var1 == var6.isCritical()) {
                  var3.add(var5.getId());
               }
            }

            return var3;
         }
      }

      return null;
   }

   public Set getCriticalExtensionOIDs() {
      return this.getExtensionOIDs(true);
   }

   public Set getNonCriticalExtensionOIDs() {
      return this.getExtensionOIDs(false);
   }

   public byte[] getExtensionValue(String var1) {
      Extensions var2 = this.c.getTBSCertList().getExtensions();
      if (var2 != null) {
         Extension var3 = var2.getExtension(new ASN1ObjectIdentifier(var1));
         if (var3 != null) {
            try {
               return var3.getExtnValue().getEncoded();
            } catch (Exception var5) {
               throw new IllegalStateException("error parsing " + var5.toString());
            }
         }
      }

      return null;
   }

   public byte[] getEncoded() throws CRLException {
      try {
         return this.c.getEncoded("DER");
      } catch (IOException var2) {
         throw new CRLException(var2.toString());
      }
   }

   public void verify(PublicKey var1) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
      this.verify(var1, BouncyCastleProvider.PROVIDER_NAME);
   }

   public void verify(PublicKey var1, String var2) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
      if (!this.c.getSignatureAlgorithm().equals(this.c.getTBSCertList().getSignature())) {
         throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
      } else {
         Signature var3;
         if (var2 != null) {
            var3 = Signature.getInstance(this.getSigAlgName(), var2);
         } else {
            var3 = Signature.getInstance(this.getSigAlgName());
         }

         var3.initVerify(var1);
         var3.update(this.getTBSCertList());
         if (!var3.verify(this.getSignature())) {
            throw new SignatureException("CRL does not verify with supplied public key.");
         }
      }
   }

   public int getVersion() {
      return this.c.getVersionNumber();
   }

   public Principal getIssuerDN() {
      return new X509Principal(X500Name.getInstance(this.c.getIssuer().toASN1Primitive()));
   }

   public X500Principal getIssuerX500Principal() {
      try {
         return new X500Principal(this.c.getIssuer().getEncoded());
      } catch (IOException var2) {
         throw new IllegalStateException("can't encode issuer DN");
      }
   }

   public Date getThisUpdate() {
      return this.c.getThisUpdate().getDate();
   }

   public Date getNextUpdate() {
      return this.c.getNextUpdate() != null ? this.c.getNextUpdate().getDate() : null;
   }

   private Set loadCRLEntries() {
      HashSet var1 = new HashSet();
      Enumeration var2 = this.c.getRevokedCertificateEnumeration();
      X500Name var3 = null;

      while(var2.hasMoreElements()) {
         TBSCertList.CRLEntry var4 = (TBSCertList.CRLEntry)var2.nextElement();
         X509CRLEntryObject var5 = new X509CRLEntryObject(var4, this.isIndirect, var3);
         var1.add(var5);
         if (this.isIndirect && var4.hasExtensions()) {
            Extension var6 = var4.getExtensions().getExtension(Extension.certificateIssuer);
            if (var6 != null) {
               var3 = X500Name.getInstance(GeneralNames.getInstance(var6.getParsedValue()).getNames()[0].getName());
            }
         }
      }

      return var1;
   }

   public X509CRLEntry getRevokedCertificate(BigInteger var1) {
      Enumeration var2 = this.c.getRevokedCertificateEnumeration();
      X500Name var3 = null;

      while(var2.hasMoreElements()) {
         TBSCertList.CRLEntry var4 = (TBSCertList.CRLEntry)var2.nextElement();
         if (var1.equals(var4.getUserCertificate().getValue())) {
            return new X509CRLEntryObject(var4, this.isIndirect, var3);
         }

         if (this.isIndirect && var4.hasExtensions()) {
            Extension var5 = var4.getExtensions().getExtension(Extension.certificateIssuer);
            if (var5 != null) {
               var3 = X500Name.getInstance(GeneralNames.getInstance(var5.getParsedValue()).getNames()[0].getName());
            }
         }
      }

      return null;
   }

   public Set getRevokedCertificates() {
      Set var1 = this.loadCRLEntries();
      return !var1.isEmpty() ? Collections.unmodifiableSet(var1) : null;
   }

   public byte[] getTBSCertList() throws CRLException {
      try {
         return this.c.getTBSCertList().getEncoded("DER");
      } catch (IOException var2) {
         throw new CRLException(var2.toString());
      }
   }

   public byte[] getSignature() {
      return this.c.getSignature().getBytes();
   }

   public String getSigAlgName() {
      return this.sigAlgName;
   }

   public String getSigAlgOID() {
      return this.c.getSignatureAlgorithm().getAlgorithm().getId();
   }

   public byte[] getSigAlgParams() {
      if (this.sigAlgParams != null) {
         byte[] var1 = new byte[this.sigAlgParams.length];
         System.arraycopy(this.sigAlgParams, 0, var1, 0, var1.length);
         return var1;
      } else {
         return null;
      }
   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      String var2 = System.getProperty("line.separator");
      var1.append("              Version: ").append(this.getVersion()).append(var2);
      var1.append("             IssuerDN: ").append(this.getIssuerDN()).append(var2);
      var1.append("          This update: ").append(this.getThisUpdate()).append(var2);
      var1.append("          Next update: ").append(this.getNextUpdate()).append(var2);
      var1.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(var2);
      byte[] var3 = this.getSignature();
      var1.append("            Signature: ").append(new String(Hex.encode(var3, 0, 20))).append(var2);

      for(int var4 = 20; var4 < var3.length; var4 += 20) {
         if (var4 < var3.length - 20) {
            var1.append("                       ").append(new String(Hex.encode(var3, var4, 20))).append(var2);
         } else {
            var1.append("                       ").append(new String(Hex.encode(var3, var4, var3.length - var4))).append(var2);
         }
      }

      Extensions var12 = this.c.getTBSCertList().getExtensions();
      if (var12 != null) {
         Enumeration var5 = var12.oids();
         if (var5.hasMoreElements()) {
            var1.append("           Extensions: ").append(var2);
         }

         while(var5.hasMoreElements()) {
            ASN1ObjectIdentifier var6 = (ASN1ObjectIdentifier)var5.nextElement();
            Extension var7 = var12.getExtension(var6);
            if (var7.getExtnValue() != null) {
               byte[] var8 = var7.getExtnValue().getOctets();
               ASN1InputStream var9 = new ASN1InputStream(var8);
               var1.append("                       critical(").append(var7.isCritical()).append(") ");

               try {
                  if (var6.equals(Extension.cRLNumber)) {
                     var1.append(new CRLNumber(ASN1Integer.getInstance(var9.readObject()).getPositiveValue())).append(var2);
                  } else if (var6.equals(Extension.deltaCRLIndicator)) {
                     var1.append("Base CRL: " + new CRLNumber(ASN1Integer.getInstance(var9.readObject()).getPositiveValue())).append(var2);
                  } else if (var6.equals(Extension.issuingDistributionPoint)) {
                     var1.append(IssuingDistributionPoint.getInstance(var9.readObject())).append(var2);
                  } else if (var6.equals(Extension.cRLDistributionPoints)) {
                     var1.append(CRLDistPoint.getInstance(var9.readObject())).append(var2);
                  } else if (var6.equals(Extension.freshestCRL)) {
                     var1.append(CRLDistPoint.getInstance(var9.readObject())).append(var2);
                  } else {
                     var1.append(var6.getId());
                     var1.append(" value = ").append(ASN1Dump.dumpAsString(var9.readObject())).append(var2);
                  }
               } catch (Exception var11) {
                  var1.append(var6.getId());
                  var1.append(" value = ").append("*****").append(var2);
               }
            } else {
               var1.append(var2);
            }
         }
      }

      Set var13 = this.getRevokedCertificates();
      if (var13 != null) {
         Iterator var14 = var13.iterator();

         while(var14.hasNext()) {
            var1.append(var14.next());
            var1.append(var2);
         }
      }

      return var1.toString();
   }

   public boolean isRevoked(Certificate var1) {
      if (!var1.getType().equals("X.509")) {
         throw new RuntimeException("X.509 CRL used with non X.509 Cert");
      } else {
         TBSCertList.CRLEntry[] var2 = this.c.getRevokedCertificates();
         X500Name var3 = this.c.getIssuer();
         if (var2 != null) {
            BigInteger var4 = ((X509Certificate)var1).getSerialNumber();

            for(int var5 = 0; var5 < var2.length; ++var5) {
               if (this.isIndirect && var2[var5].hasExtensions()) {
                  Extension var6 = var2[var5].getExtensions().getExtension(Extension.certificateIssuer);
                  if (var6 != null) {
                     var3 = X500Name.getInstance(GeneralNames.getInstance(var6.getParsedValue()).getNames()[0].getName());
                  }
               }

               if (var2[var5].getUserCertificate().getValue().equals(var4)) {
                  X500Name var9;
                  if (var1 instanceof X509Certificate) {
                     var9 = X500Name.getInstance(((X509Certificate)var1).getIssuerX500Principal().getEncoded());
                  } else {
                     try {
                        var9 = org.bc.asn1.x509.Certificate.getInstance(var1.getEncoded()).getIssuer();
                     } catch (CertificateEncodingException var8) {
                        throw new RuntimeException("Cannot process certificate");
                     }
                  }

                  if (!var3.equals(var9)) {
                     return false;
                  }

                  return true;
               }
            }
         }

         return false;
      }
   }
}
