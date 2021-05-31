package org.bc.ocsp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1GeneralizedTime;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERGeneralizedTime;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DERSequence;
import org.bc.asn1.ocsp.BasicOCSPResponse;
import org.bc.asn1.ocsp.CertStatus;
import org.bc.asn1.ocsp.ResponseData;
import org.bc.asn1.ocsp.RevokedInfo;
import org.bc.asn1.ocsp.SingleResponse;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.CRLReason;
import org.bc.asn1.x509.X509CertificateStructure;
import org.bc.asn1.x509.X509Extensions;

/** @deprecated */
public class BasicOCSPRespGenerator {
   private List list = new ArrayList();
   private X509Extensions responseExtensions = null;
   private RespID responderID;

   public BasicOCSPRespGenerator(RespID var1) {
      this.responderID = var1;
   }

   public BasicOCSPRespGenerator(PublicKey var1) throws OCSPException {
      this.responderID = new RespID(var1);
   }

   public void addResponse(CertificateID var1, CertificateStatus var2) {
      this.list.add(new BasicOCSPRespGenerator.ResponseObject(var1, var2, new Date(), (Date)null, (X509Extensions)null));
   }

   public void addResponse(CertificateID var1, CertificateStatus var2, X509Extensions var3) {
      this.list.add(new BasicOCSPRespGenerator.ResponseObject(var1, var2, new Date(), (Date)null, var3));
   }

   public void addResponse(CertificateID var1, CertificateStatus var2, Date var3, X509Extensions var4) {
      this.list.add(new BasicOCSPRespGenerator.ResponseObject(var1, var2, new Date(), var3, var4));
   }

   public void addResponse(CertificateID var1, CertificateStatus var2, Date var3, Date var4, X509Extensions var5) {
      this.list.add(new BasicOCSPRespGenerator.ResponseObject(var1, var2, var3, var4, var5));
   }

   public void setResponseExtensions(X509Extensions var1) {
      this.responseExtensions = var1;
   }

   private BasicOCSPResp generateResponse(String var1, PrivateKey var2, X509Certificate[] var3, Date var4, String var5, SecureRandom var6) throws OCSPException, NoSuchProviderException {
      Iterator var7 = this.list.iterator();

      DERObjectIdentifier var8;
      try {
         var8 = OCSPUtil.getAlgorithmOID(var1);
      } catch (Exception var21) {
         throw new IllegalArgumentException("unknown signing algorithm specified");
      }

      ASN1EncodableVector var9 = new ASN1EncodableVector();

      while(var7.hasNext()) {
         try {
            var9.add(((BasicOCSPRespGenerator.ResponseObject)var7.next()).toResponse());
         } catch (Exception var20) {
            throw new OCSPException("exception creating Request", var20);
         }
      }

      ResponseData var10 = new ResponseData(this.responderID.toASN1Object(), new DERGeneralizedTime(var4), new DERSequence(var9), this.responseExtensions);
      Signature var11 = null;

      try {
         var11 = OCSPUtil.createSignatureInstance(var1, var5);
         if (var6 != null) {
            var11.initSign(var2, var6);
         } else {
            var11.initSign(var2);
         }
      } catch (NoSuchProviderException var18) {
         throw var18;
      } catch (GeneralSecurityException var19) {
         throw new OCSPException("exception creating signature: " + var19, var19);
      }

      DERBitString var12 = null;

      try {
         var11.update(var10.getEncoded("DER"));
         var12 = new DERBitString(var11.sign());
      } catch (Exception var17) {
         throw new OCSPException("exception processing TBSRequest: " + var17, var17);
      }

      AlgorithmIdentifier var13 = OCSPUtil.getSigAlgID(var8);
      DERSequence var14 = null;
      if (var3 != null && var3.length > 0) {
         ASN1EncodableVector var15 = new ASN1EncodableVector();

         try {
            for(int var16 = 0; var16 != var3.length; ++var16) {
               var15.add(new X509CertificateStructure((ASN1Sequence)ASN1Primitive.fromByteArray(var3[var16].getEncoded())));
            }
         } catch (IOException var22) {
            throw new OCSPException("error processing certs", var22);
         } catch (CertificateEncodingException var23) {
            throw new OCSPException("error encoding certs", var23);
         }

         var14 = new DERSequence(var15);
      }

      return new BasicOCSPResp(new BasicOCSPResponse(var10, var13, var12, var14));
   }

   public BasicOCSPResp generate(String var1, PrivateKey var2, X509Certificate[] var3, Date var4, String var5) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
      return this.generate(var1, var2, var3, var4, var5, (SecureRandom)null);
   }

   public BasicOCSPResp generate(String var1, PrivateKey var2, X509Certificate[] var3, Date var4, String var5, SecureRandom var6) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
      if (var1 == null) {
         throw new IllegalArgumentException("no signing algorithm specified");
      } else {
         return this.generateResponse(var1, var2, var3, var4, var5, var6);
      }
   }

   public Iterator getSignatureAlgNames() {
      return OCSPUtil.getAlgNames();
   }

   private class ResponseObject {
      CertificateID certId;
      CertStatus certStatus;
      DERGeneralizedTime thisUpdate;
      DERGeneralizedTime nextUpdate;
      X509Extensions extensions;

      public ResponseObject(CertificateID var2, CertificateStatus var3, Date var4, Date var5, X509Extensions var6) {
         this.certId = var2;
         if (var3 == null) {
            this.certStatus = new CertStatus();
         } else if (var3 instanceof UnknownStatus) {
            this.certStatus = new CertStatus(2, DERNull.INSTANCE);
         } else {
            RevokedStatus var7 = (RevokedStatus)var3;
            if (var7.hasRevocationReason()) {
               this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(var7.getRevocationTime()), CRLReason.lookup(var7.getRevocationReason())));
            } else {
               this.certStatus = new CertStatus(new RevokedInfo(new ASN1GeneralizedTime(var7.getRevocationTime()), (CRLReason)null));
            }
         }

         this.thisUpdate = new DERGeneralizedTime(var4);
         if (var5 != null) {
            this.nextUpdate = new DERGeneralizedTime(var5);
         } else {
            this.nextUpdate = null;
         }

         this.extensions = var6;
      }

      public SingleResponse toResponse() throws Exception {
         return new SingleResponse(this.certId.toASN1Object(), this.certStatus, this.thisUpdate, this.nextUpdate, this.extensions);
      }
   }
}
