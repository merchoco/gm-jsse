package org.bc.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OutputStream;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ocsp.OCSPRequest;
import org.bc.asn1.ocsp.Request;
import org.bc.asn1.x509.GeneralName;
import org.bc.asn1.x509.X509Extensions;

/** @deprecated */
public class OCSPReq implements X509Extension {
   private OCSPRequest req;

   public OCSPReq(OCSPRequest var1) {
      this.req = var1;
   }

   public OCSPReq(byte[] var1) throws IOException {
      this(new ASN1InputStream(var1));
   }

   public OCSPReq(InputStream var1) throws IOException {
      this(new ASN1InputStream(var1));
   }

   private OCSPReq(ASN1InputStream var1) throws IOException {
      try {
         this.req = OCSPRequest.getInstance(var1.readObject());
      } catch (IllegalArgumentException var3) {
         throw new IOException("malformed request: " + var3.getMessage());
      } catch (ClassCastException var4) {
         throw new IOException("malformed request: " + var4.getMessage());
      }
   }

   public byte[] getTBSRequest() throws OCSPException {
      try {
         return this.req.getTbsRequest().getEncoded();
      } catch (IOException var2) {
         throw new OCSPException("problem encoding tbsRequest", var2);
      }
   }

   public int getVersion() {
      return this.req.getTbsRequest().getVersion().getValue().intValue() + 1;
   }

   public GeneralName getRequestorName() {
      return GeneralName.getInstance(this.req.getTbsRequest().getRequestorName());
   }

   public Req[] getRequestList() {
      ASN1Sequence var1 = this.req.getTbsRequest().getRequestList();
      Req[] var2 = new Req[var1.size()];

      for(int var3 = 0; var3 != var2.length; ++var3) {
         var2[var3] = new Req(Request.getInstance(var1.getObjectAt(var3)));
      }

      return var2;
   }

   public X509Extensions getRequestExtensions() {
      return X509Extensions.getInstance(this.req.getTbsRequest().getRequestExtensions());
   }

   public String getSignatureAlgOID() {
      return !this.isSigned() ? null : this.req.getOptionalSignature().getSignatureAlgorithm().getObjectId().getId();
   }

   public byte[] getSignature() {
      return !this.isSigned() ? null : this.req.getOptionalSignature().getSignature().getBytes();
   }

   private List getCertList(String var1) throws OCSPException, NoSuchProviderException {
      ArrayList var2 = new ArrayList();
      ByteArrayOutputStream var3 = new ByteArrayOutputStream();
      ASN1OutputStream var4 = new ASN1OutputStream(var3);

      CertificateFactory var5;
      try {
         var5 = OCSPUtil.createX509CertificateFactory(var1);
      } catch (CertificateException var11) {
         throw new OCSPException("can't get certificate factory.", var11);
      }

      ASN1Sequence var6 = this.req.getOptionalSignature().getCerts();
      if (var6 != null) {
         for(Enumeration var7 = var6.getObjects(); var7.hasMoreElements(); var3.reset()) {
            try {
               var4.writeObject((ASN1Encodable)var7.nextElement());
               var2.add(var5.generateCertificate(new ByteArrayInputStream(var3.toByteArray())));
            } catch (IOException var9) {
               throw new OCSPException("can't re-encode certificate!", var9);
            } catch (CertificateException var10) {
               throw new OCSPException("can't re-encode certificate!", var10);
            }
         }
      }

      return var2;
   }

   public X509Certificate[] getCerts(String var1) throws OCSPException, NoSuchProviderException {
      if (!this.isSigned()) {
         return null;
      } else {
         List var2 = this.getCertList(var1);
         return (X509Certificate[])var2.toArray(new X509Certificate[var2.size()]);
      }
   }

   public CertStore getCertificates(String var1, String var2) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
      if (!this.isSigned()) {
         return null;
      } else {
         try {
            CollectionCertStoreParameters var3 = new CollectionCertStoreParameters(this.getCertList(var2));
            return OCSPUtil.createCertStoreInstance(var1, var3, var2);
         } catch (InvalidAlgorithmParameterException var4) {
            throw new OCSPException("can't setup the CertStore", var4);
         }
      }
   }

   public boolean isSigned() {
      return this.req.getOptionalSignature() != null;
   }

   public boolean verify(PublicKey var1, String var2) throws OCSPException, NoSuchProviderException {
      if (!this.isSigned()) {
         throw new OCSPException("attempt to verify signature on unsigned object");
      } else {
         try {
            Signature var3 = OCSPUtil.createSignatureInstance(this.getSignatureAlgOID(), var2);
            var3.initVerify(var1);
            ByteArrayOutputStream var4 = new ByteArrayOutputStream();
            ASN1OutputStream var5 = new ASN1OutputStream(var4);
            var5.writeObject(this.req.getTbsRequest());
            var3.update(var4.toByteArray());
            return var3.verify(this.getSignature());
         } catch (NoSuchProviderException var6) {
            throw var6;
         } catch (Exception var7) {
            throw new OCSPException("exception processing sig: " + var7, var7);
         }
      }
   }

   public byte[] getEncoded() throws IOException {
      ByteArrayOutputStream var1 = new ByteArrayOutputStream();
      ASN1OutputStream var2 = new ASN1OutputStream(var1);
      var2.writeObject(this.req);
      return var1.toByteArray();
   }

   public boolean hasUnsupportedCriticalExtension() {
      Set var1 = this.getCriticalExtensionOIDs();
      return var1 != null && !var1.isEmpty();
   }

   private Set getExtensionOIDs(boolean var1) {
      HashSet var2 = new HashSet();
      X509Extensions var3 = this.getRequestExtensions();
      if (var3 != null) {
         Enumeration var4 = var3.oids();

         while(var4.hasMoreElements()) {
            ASN1ObjectIdentifier var5 = (ASN1ObjectIdentifier)var4.nextElement();
            org.bc.asn1.x509.X509Extension var6 = var3.getExtension(var5);
            if (var1 == var6.isCritical()) {
               var2.add(var5.getId());
            }
         }
      }

      return var2;
   }

   public Set getCriticalExtensionOIDs() {
      return this.getExtensionOIDs(true);
   }

   public Set getNonCriticalExtensionOIDs() {
      return this.getExtensionOIDs(false);
   }

   public byte[] getExtensionValue(String var1) {
      X509Extensions var2 = this.getRequestExtensions();
      if (var2 != null) {
         org.bc.asn1.x509.X509Extension var3 = var2.getExtension(new ASN1ObjectIdentifier(var1));
         if (var3 != null) {
            try {
               return var3.getValue().getEncoded("DER");
            } catch (Exception var5) {
               throw new RuntimeException("error encoding " + var5.toString());
            }
         }
      }

      return null;
   }
}
