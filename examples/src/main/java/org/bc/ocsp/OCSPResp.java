package org.bc.ocsp;

import java.io.IOException;
import java.io.InputStream;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ocsp.BasicOCSPResponse;
import org.bc.asn1.ocsp.OCSPObjectIdentifiers;
import org.bc.asn1.ocsp.OCSPResponse;
import org.bc.asn1.ocsp.ResponseBytes;

/** @deprecated */
public class OCSPResp {
   private OCSPResponse resp;

   /** @deprecated */
   public OCSPResp(OCSPResponse var1) {
      this.resp = var1;
   }

   /** @deprecated */
   public OCSPResp(byte[] var1) throws IOException {
      this(new ASN1InputStream(var1));
   }

   /** @deprecated */
   public OCSPResp(InputStream var1) throws IOException {
      this(new ASN1InputStream(var1));
   }

   private OCSPResp(ASN1InputStream var1) throws IOException {
      try {
         this.resp = OCSPResponse.getInstance(var1.readObject());
      } catch (IllegalArgumentException var3) {
         throw new IOException("malformed response: " + var3.getMessage());
      } catch (ClassCastException var4) {
         throw new IOException("malformed response: " + var4.getMessage());
      }
   }

   public int getStatus() {
      return this.resp.getResponseStatus().getValue().intValue();
   }

   public Object getResponseObject() throws OCSPException {
      ResponseBytes var1 = this.resp.getResponseBytes();
      if (var1 == null) {
         return null;
      } else if (var1.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
         try {
            ASN1Primitive var2 = ASN1Primitive.fromByteArray(var1.getResponse().getOctets());
            return new BasicOCSPResp(BasicOCSPResponse.getInstance(var2));
         } catch (Exception var3) {
            throw new OCSPException("problem decoding object: " + var3, var3);
         }
      } else {
         return var1.getResponse();
      }
   }

   public byte[] getEncoded() throws IOException {
      return this.resp.getEncoded();
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (!(var1 instanceof OCSPResp)) {
         return false;
      } else {
         OCSPResp var2 = (OCSPResp)var1;
         return this.resp.equals(var2.resp);
      }
   }

   public int hashCode() {
      return this.resp.hashCode();
   }
}
