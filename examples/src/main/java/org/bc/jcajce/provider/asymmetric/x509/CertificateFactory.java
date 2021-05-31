package org.bc.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1Set;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.pkcs.SignedData;
import org.bc.asn1.x509.CertificateList;
import org.bc.jce.provider.X509CRLObject;
import org.bc.jce.provider.X509CertificateObject;

public class CertificateFactory extends CertificateFactorySpi {
   private static final PEMUtil PEM_CERT_PARSER = new PEMUtil("CERTIFICATE");
   private static final PEMUtil PEM_CRL_PARSER = new PEMUtil("CRL");
   private ASN1Set sData = null;
   private int sDataObjectCount = 0;
   private InputStream currentStream = null;
   private ASN1Set sCrlData = null;
   private int sCrlDataObjectCount = 0;
   private InputStream currentCrlStream = null;

   private Certificate readDERCertificate(ASN1InputStream var1) throws IOException, CertificateParsingException {
      ASN1Sequence var2 = (ASN1Sequence)var1.readObject();
      if (var2.size() > 1 && var2.getObjectAt(0) instanceof ASN1ObjectIdentifier && var2.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData)) {
         this.sData = SignedData.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)var2.getObjectAt(1), true)).getCertificates();
         return this.getCertificate();
      } else {
         return new X509CertificateObject(org.bc.asn1.x509.Certificate.getInstance(var2));
      }
   }

   private Certificate getCertificate() throws CertificateParsingException {
      if (this.sData != null) {
         while(this.sDataObjectCount < this.sData.size()) {
            ASN1Encodable var1 = this.sData.getObjectAt(this.sDataObjectCount++);
            if (var1 instanceof ASN1Sequence) {
               return new X509CertificateObject(org.bc.asn1.x509.Certificate.getInstance(var1));
            }
         }
      }

      return null;
   }

   private Certificate readPEMCertificate(InputStream var1) throws IOException, CertificateParsingException {
      ASN1Sequence var2 = PEM_CERT_PARSER.readPEMObject(var1);
      return var2 != null ? new X509CertificateObject(org.bc.asn1.x509.Certificate.getInstance(var2)) : null;
   }

   protected CRL createCRL(CertificateList var1) throws CRLException {
      return new X509CRLObject(var1);
   }

   private CRL readPEMCRL(InputStream var1) throws IOException, CRLException {
      ASN1Sequence var2 = PEM_CRL_PARSER.readPEMObject(var1);
      return var2 != null ? this.createCRL(CertificateList.getInstance(var2)) : null;
   }

   private CRL readDERCRL(ASN1InputStream var1) throws IOException, CRLException {
      ASN1Sequence var2 = (ASN1Sequence)var1.readObject();
      if (var2.size() > 1 && var2.getObjectAt(0) instanceof ASN1ObjectIdentifier && var2.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData)) {
         this.sCrlData = SignedData.getInstance(ASN1Sequence.getInstance((ASN1TaggedObject)var2.getObjectAt(1), true)).getCRLs();
         return this.getCRL();
      } else {
         return this.createCRL(CertificateList.getInstance(var2));
      }
   }

   private CRL getCRL() throws CRLException {
      return this.sCrlData != null && this.sCrlDataObjectCount < this.sCrlData.size() ? this.createCRL(CertificateList.getInstance(this.sCrlData.getObjectAt(this.sCrlDataObjectCount++))) : null;
   }

   public Certificate engineGenerateCertificate(InputStream var1) throws CertificateException {
      if (this.currentStream == null) {
         this.currentStream = var1;
         this.sData = null;
         this.sDataObjectCount = 0;
      } else if (this.currentStream != var1) {
         this.currentStream = var1;
         this.sData = null;
         this.sDataObjectCount = 0;
      }

      try {
         if (this.sData != null) {
            if (this.sDataObjectCount != this.sData.size()) {
               return this.getCertificate();
            } else {
               this.sData = null;
               this.sDataObjectCount = 0;
               return null;
            }
         } else {
            PushbackInputStream var2 = new PushbackInputStream(var1);
            int var3 = var2.read();
            if (var3 == -1) {
               return null;
            } else {
               var2.unread(var3);
               return var3 != 48 ? this.readPEMCertificate(var2) : this.readDERCertificate(new ASN1InputStream(var2));
            }
         }
      } catch (Exception var4) {
         throw new CertificateFactory.ExCertificateException(var4);
      }
   }

   public Collection engineGenerateCertificates(InputStream var1) throws CertificateException {
      ArrayList var3 = new ArrayList();

      Certificate var2;
      while((var2 = this.engineGenerateCertificate(var1)) != null) {
         var3.add(var2);
      }

      return var3;
   }

   public CRL engineGenerateCRL(InputStream var1) throws CRLException {
      if (this.currentCrlStream == null) {
         this.currentCrlStream = var1;
         this.sCrlData = null;
         this.sCrlDataObjectCount = 0;
      } else if (this.currentCrlStream != var1) {
         this.currentCrlStream = var1;
         this.sCrlData = null;
         this.sCrlDataObjectCount = 0;
      }

      try {
         if (this.sCrlData != null) {
            if (this.sCrlDataObjectCount != this.sCrlData.size()) {
               return this.getCRL();
            } else {
               this.sCrlData = null;
               this.sCrlDataObjectCount = 0;
               return null;
            }
         } else {
            PushbackInputStream var2 = new PushbackInputStream(var1);
            int var3 = var2.read();
            if (var3 == -1) {
               return null;
            } else {
               var2.unread(var3);
               return var3 != 48 ? this.readPEMCRL(var2) : this.readDERCRL(new ASN1InputStream(var2, true));
            }
         }
      } catch (CRLException var4) {
         throw var4;
      } catch (Exception var5) {
         throw new CRLException(var5.toString());
      }
   }

   public Collection engineGenerateCRLs(InputStream var1) throws CRLException {
      ArrayList var3 = new ArrayList();

      CRL var2;
      while((var2 = this.engineGenerateCRL(var1)) != null) {
         var3.add(var2);
      }

      return var3;
   }

   public Iterator engineGetCertPathEncodings() {
      return null;
   }

   public CertPath engineGenerateCertPath(InputStream var1) throws CertificateException {
      return this.engineGenerateCertPath(var1, "PkiPath");
   }

   public CertPath engineGenerateCertPath(InputStream var1, String var2) throws CertificateException {
      return new PKIXCertPath(var1, var2);
   }

   public CertPath engineGenerateCertPath(List var1) throws CertificateException {
      Iterator var2 = var1.iterator();

      Object var3;
      do {
         if (!var2.hasNext()) {
            return new PKIXCertPath(var1);
         }

         var3 = var2.next();
      } while(var3 == null || var3 instanceof X509Certificate);

      throw new CertificateException("list contains non X509Certificate object while creating CertPath\n" + var3.toString());
   }

   private class ExCertificateException extends CertificateException {
      private Throwable cause;

      public ExCertificateException(Throwable var2) {
         this.cause = var2;
      }

      public ExCertificateException(String var2, Throwable var3) {
         super(var2);
         this.cause = var3;
      }

      public Throwable getCause() {
         return this.cause;
      }
   }
}
