package org.bc.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1OutputStream;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DERSequence;
import org.bc.asn1.ocsp.OCSPRequest;
import org.bc.asn1.ocsp.Request;
import org.bc.asn1.ocsp.TBSRequest;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.Extensions;
import org.bc.asn1.x509.GeneralName;
import org.bc.asn1.x509.X509CertificateStructure;
import org.bc.asn1.x509.X509Extensions;
import org.bc.jce.X509Principal;

/** @deprecated */
public class OCSPReqGenerator {
   private List list = new ArrayList();
   private GeneralName requestorName = null;
   private X509Extensions requestExtensions = null;

   public void addRequest(CertificateID var1) {
      this.list.add(new OCSPReqGenerator.RequestObject(var1, (X509Extensions)null));
   }

   public void addRequest(CertificateID var1, X509Extensions var2) {
      this.list.add(new OCSPReqGenerator.RequestObject(var1, var2));
   }

   public void setRequestorName(X500Principal var1) {
      try {
         this.requestorName = new GeneralName(4, new X509Principal(var1.getEncoded()));
      } catch (IOException var3) {
         throw new IllegalArgumentException("cannot encode principal: " + var3);
      }
   }

   public void setRequestorName(GeneralName var1) {
      this.requestorName = var1;
   }

   public void setRequestExtensions(X509Extensions var1) {
      this.requestExtensions = var1;
   }

   private OCSPReq generateRequest(DERObjectIdentifier var1, PrivateKey var2, X509Certificate[] var3, String var4, SecureRandom var5) throws OCSPException, NoSuchProviderException {
      Iterator var6 = this.list.iterator();
      ASN1EncodableVector var7 = new ASN1EncodableVector();

      while(var6.hasNext()) {
         try {
            var7.add(((OCSPReqGenerator.RequestObject)var6.next()).toRequest());
         } catch (Exception var18) {
            throw new OCSPException("exception creating Request", var18);
         }
      }

      TBSRequest var8 = new TBSRequest(this.requestorName, new DERSequence(var7), this.requestExtensions);
      Signature var9 = null;
      org.bc.asn1.ocsp.Signature var10 = null;
      if (var1 != null) {
         if (this.requestorName == null) {
            throw new OCSPException("requestorName must be specified if request is signed.");
         }

         try {
            var9 = OCSPUtil.createSignatureInstance(var1.getId(), var4);
            if (var5 != null) {
               var9.initSign(var2, var5);
            } else {
               var9.initSign(var2);
            }
         } catch (NoSuchProviderException var16) {
            throw var16;
         } catch (GeneralSecurityException var17) {
            throw new OCSPException("exception creating signature: " + var17, var17);
         }

         DERBitString var11 = null;

         try {
            ByteArrayOutputStream var12 = new ByteArrayOutputStream();
            ASN1OutputStream var13 = new ASN1OutputStream(var12);
            var13.writeObject(var8);
            var9.update(var12.toByteArray());
            var11 = new DERBitString(var9.sign());
         } catch (Exception var15) {
            throw new OCSPException("exception processing TBSRequest: " + var15, var15);
         }

         AlgorithmIdentifier var21 = new AlgorithmIdentifier(var1, DERNull.INSTANCE);
         if (var3 != null && var3.length > 0) {
            ASN1EncodableVector var22 = new ASN1EncodableVector();

            try {
               for(int var14 = 0; var14 != var3.length; ++var14) {
                  var22.add(new X509CertificateStructure((ASN1Sequence)ASN1Primitive.fromByteArray(var3[var14].getEncoded())));
               }
            } catch (IOException var19) {
               throw new OCSPException("error processing certs", var19);
            } catch (CertificateEncodingException var20) {
               throw new OCSPException("error encoding certs", var20);
            }

            var10 = new org.bc.asn1.ocsp.Signature(var21, var11, new DERSequence(var22));
         } else {
            var10 = new org.bc.asn1.ocsp.Signature(var21, var11);
         }
      }

      return new OCSPReq(new OCSPRequest(var8, var10));
   }

   public OCSPReq generate() throws OCSPException {
      try {
         return this.generateRequest((DERObjectIdentifier)null, (PrivateKey)null, (X509Certificate[])null, (String)null, (SecureRandom)null);
      } catch (NoSuchProviderException var2) {
         throw new OCSPException("no provider! - " + var2, var2);
      }
   }

   public OCSPReq generate(String var1, PrivateKey var2, X509Certificate[] var3, String var4) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
      return this.generate(var1, var2, var3, var4, (SecureRandom)null);
   }

   public OCSPReq generate(String var1, PrivateKey var2, X509Certificate[] var3, String var4, SecureRandom var5) throws OCSPException, NoSuchProviderException, IllegalArgumentException {
      if (var1 == null) {
         throw new IllegalArgumentException("no signing algorithm specified");
      } else {
         try {
            DERObjectIdentifier var6 = OCSPUtil.getAlgorithmOID(var1);
            return this.generateRequest(var6, var2, var3, var4, var5);
         } catch (IllegalArgumentException var7) {
            throw new IllegalArgumentException("unknown signing algorithm specified: " + var1);
         }
      }
   }

   public Iterator getSignatureAlgNames() {
      return OCSPUtil.getAlgNames();
   }

   private class RequestObject {
      CertificateID certId;
      X509Extensions extensions;

      public RequestObject(CertificateID var2, X509Extensions var3) {
         this.certId = var2;
         this.extensions = var3;
      }

      public Request toRequest() throws Exception {
         return new Request(this.certId.toASN1Object(), Extensions.getInstance(this.extensions));
      }
   }
}
