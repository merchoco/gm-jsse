package org.bc.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1OutputStream;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.ocsp.BasicOCSPResponse;
import org.bc.asn1.ocsp.ResponseData;
import org.bc.asn1.ocsp.SingleResponse;
import org.bc.asn1.x509.X509Extensions;

/** @deprecated */
public class BasicOCSPResp implements X509Extension {
   BasicOCSPResponse resp;
   ResponseData data;
   X509Certificate[] chain = null;

   public BasicOCSPResp(BasicOCSPResponse var1) {
      this.resp = var1;
      this.data = var1.getTbsResponseData();
   }

   public byte[] getTBSResponseData() throws OCSPException {
      try {
         return this.resp.getTbsResponseData().getEncoded();
      } catch (IOException var2) {
         throw new OCSPException("problem encoding tbsResponseData", var2);
      }
   }

   public int getVersion() {
      return this.data.getVersion().getValue().intValue() + 1;
   }

   public RespID getResponderId() {
      return new RespID(this.data.getResponderID());
   }

   public Date getProducedAt() {
      try {
         return this.data.getProducedAt().getDate();
      } catch (ParseException var2) {
         throw new IllegalStateException("ParseException:" + var2.getMessage());
      }
   }

   public SingleResp[] getResponses() {
      ASN1Sequence var1 = this.data.getResponses();
      SingleResp[] var2 = new SingleResp[var1.size()];

      for(int var3 = 0; var3 != var2.length; ++var3) {
         var2[var3] = new SingleResp(SingleResponse.getInstance(var1.getObjectAt(var3)));
      }

      return var2;
   }

   public X509Extensions getResponseExtensions() {
      return X509Extensions.getInstance(this.data.getResponseExtensions());
   }

   public boolean hasUnsupportedCriticalExtension() {
      Set var1 = this.getCriticalExtensionOIDs();
      return var1 != null && !var1.isEmpty();
   }

   private Set getExtensionOIDs(boolean var1) {
      HashSet var2 = new HashSet();
      X509Extensions var3 = this.getResponseExtensions();
      if (var3 != null) {
         Enumeration var4 = var3.oids();

         while(var4.hasMoreElements()) {
            DERObjectIdentifier var5 = (DERObjectIdentifier)var4.nextElement();
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
      X509Extensions var2 = this.getResponseExtensions();
      if (var2 != null) {
         org.bc.asn1.x509.X509Extension var3 = var2.getExtension(new DERObjectIdentifier(var1));
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

   public String getSignatureAlgName() {
      return OCSPUtil.getAlgorithmName(this.resp.getSignatureAlgorithm().getObjectId());
   }

   public String getSignatureAlgOID() {
      return this.resp.getSignatureAlgorithm().getObjectId().getId();
   }

   /** @deprecated */
   public RespData getResponseData() {
      return new RespData(this.resp.getTbsResponseData());
   }

   public byte[] getSignature() {
      return this.resp.getSignature().getBytes();
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

      ASN1Sequence var6 = this.resp.getCerts();
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
      List var2 = this.getCertList(var1);
      return (X509Certificate[])var2.toArray(new X509Certificate[var2.size()]);
   }

   public CertStore getCertificates(String var1, String var2) throws NoSuchAlgorithmException, NoSuchProviderException, OCSPException {
      try {
         CollectionCertStoreParameters var3 = new CollectionCertStoreParameters(this.getCertList(var2));
         return OCSPUtil.createCertStoreInstance(var1, var3, var2);
      } catch (InvalidAlgorithmParameterException var4) {
         throw new OCSPException("can't setup the CertStore", var4);
      }
   }

   public boolean verify(PublicKey var1, String var2) throws OCSPException, NoSuchProviderException {
      try {
         Signature var3 = OCSPUtil.createSignatureInstance(this.getSignatureAlgName(), var2);
         var3.initVerify(var1);
         var3.update(this.resp.getTbsResponseData().getEncoded("DER"));
         return var3.verify(this.getSignature());
      } catch (NoSuchProviderException var4) {
         throw var4;
      } catch (Exception var5) {
         throw new OCSPException("exception processing sig: " + var5, var5);
      }
   }

   public byte[] getEncoded() throws IOException {
      return this.resp.getEncoded();
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (!(var1 instanceof BasicOCSPResp)) {
         return false;
      } else {
         BasicOCSPResp var2 = (BasicOCSPResp)var1;
         return this.resp.equals(var2.resp);
      }
   }

   public int hashCode() {
      return this.resp.hashCode();
   }
}
