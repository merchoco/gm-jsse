package org.bc.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1ParsingException;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERApplicationSpecific;
import org.bc.asn1.DEROctetString;

public class CVCertificateRequest extends ASN1Object {
   private CertificateBody certificateBody;
   private byte[] innerSignature = null;
   private byte[] outerSignature = null;
   private int valid;
   private static int bodyValid = 1;
   private static int signValid = 2;
   ASN1ObjectIdentifier signOid = null;
   ASN1ObjectIdentifier keyOid = null;
   public static byte[] ZeroArray = new byte[1];
   String strCertificateHolderReference;
   byte[] encodedAuthorityReference;
   int ProfileId;
   byte[] certificate = null;
   protected String overSignerReference = null;
   byte[] encoded;
   PublicKeyDataObject iso7816PubKey = null;

   private CVCertificateRequest(DERApplicationSpecific var1) throws IOException {
      if (var1.getApplicationTag() == 103) {
         ASN1Sequence var2 = ASN1Sequence.getInstance(var1.getObject(16));
         this.initCertBody(DERApplicationSpecific.getInstance(var2.getObjectAt(0)));
         this.outerSignature = DERApplicationSpecific.getInstance(var2.getObjectAt(var2.size() - 1)).getContents();
      } else {
         this.initCertBody(var1);
      }

   }

   private void initCertBody(DERApplicationSpecific var1) throws IOException {
      if (var1.getApplicationTag() != 33) {
         throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + var1.getApplicationTag());
      } else {
         ASN1Sequence var2 = ASN1Sequence.getInstance(var1.getObject(16));
         Enumeration var3 = var2.getObjects();

         while(var3.hasMoreElements()) {
            DERApplicationSpecific var4 = DERApplicationSpecific.getInstance(var3.nextElement());
            switch(var4.getApplicationTag()) {
            case 55:
               this.innerSignature = var4.getContents();
               this.valid |= signValid;
               break;
            case 78:
               this.certificateBody = CertificateBody.getInstance(var4);
               this.valid |= bodyValid;
               break;
            default:
               throw new IOException("Invalid tag, not an CV Certificate Request element:" + var4.getApplicationTag());
            }
         }

      }
   }

   public static CVCertificateRequest getInstance(Object var0) {
      if (var0 instanceof CVCertificateRequest) {
         return (CVCertificateRequest)var0;
      } else if (var0 != null) {
         try {
            return new CVCertificateRequest(DERApplicationSpecific.getInstance(var0));
         } catch (IOException var2) {
            throw new ASN1ParsingException("unable to parse data: " + var2.getMessage(), var2);
         }
      } else {
         return null;
      }
   }

   public CertificateBody getCertificateBody() {
      return this.certificateBody;
   }

   public PublicKeyDataObject getPublicKey() {
      return this.certificateBody.getPublicKey();
   }

   public byte[] getInnerSignature() {
      return this.innerSignature;
   }

   public byte[] getOuterSignature() {
      return this.outerSignature;
   }

   public boolean hasOuterSignature() {
      return this.outerSignature != null;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.certificateBody);

      try {
         var1.add(new DERApplicationSpecific(false, 55, new DEROctetString(this.innerSignature)));
      } catch (IOException var3) {
         throw new IllegalStateException("unable to convert signature!");
      }

      return new DERApplicationSpecific(33, var1);
   }
}
