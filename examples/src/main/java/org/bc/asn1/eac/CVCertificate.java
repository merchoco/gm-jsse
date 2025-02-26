package org.bc.asn1.eac;

import java.io.IOException;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1ParsingException;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERApplicationSpecific;
import org.bc.asn1.DEROctetString;

public class CVCertificate extends ASN1Object {
   private CertificateBody certificateBody;
   private byte[] signature;
   private int valid;
   private static int bodyValid = 1;
   private static int signValid = 2;
   public static final byte version_1 = 0;
   public static String ReferenceEncoding = "ISO-8859-1";

   private void setPrivateData(DERApplicationSpecific var1) throws IOException {
      this.valid = 0;
      if (var1.getApplicationTag() != 33) {
         throw new IOException("not a CARDHOLDER_CERTIFICATE :" + var1.getApplicationTag());
      } else {
         ASN1InputStream var2 = new ASN1InputStream(var1.getContents());

         ASN1Primitive var3;
         while((var3 = var2.readObject()) != null) {
            if (!(var3 instanceof DERApplicationSpecific)) {
               throw new IOException("Invalid Object, not an Iso7816CertificateStructure");
            }

            DERApplicationSpecific var4 = (DERApplicationSpecific)var3;
            switch(var4.getApplicationTag()) {
            case 55:
               this.signature = var4.getContents();
               this.valid |= signValid;
               break;
            case 78:
               this.certificateBody = CertificateBody.getInstance(var4);
               this.valid |= bodyValid;
               break;
            default:
               throw new IOException("Invalid tag, not an Iso7816CertificateStructure :" + var4.getApplicationTag());
            }
         }

      }
   }

   public CVCertificate(ASN1InputStream var1) throws IOException {
      this.initFrom(var1);
   }

   private void initFrom(ASN1InputStream var1) throws IOException {
      ASN1Primitive var2;
      while((var2 = var1.readObject()) != null) {
         if (!(var2 instanceof DERApplicationSpecific)) {
            throw new IOException("Invalid Input Stream for creating an Iso7816CertificateStructure");
         }

         this.setPrivateData((DERApplicationSpecific)var2);
      }

   }

   private CVCertificate(DERApplicationSpecific var1) throws IOException {
      this.setPrivateData(var1);
   }

   public CVCertificate(CertificateBody var1, byte[] var2) throws IOException {
      this.certificateBody = var1;
      this.signature = var2;
      this.valid |= bodyValid;
      this.valid |= signValid;
   }

   public static CVCertificate getInstance(Object var0) {
      if (var0 instanceof CVCertificate) {
         return (CVCertificate)var0;
      } else if (var0 != null) {
         try {
            return new CVCertificate(DERApplicationSpecific.getInstance(var0));
         } catch (IOException var2) {
            throw new ASN1ParsingException("unable to parse data: " + var2.getMessage(), var2);
         }
      } else {
         return null;
      }
   }

   public byte[] getSignature() {
      return this.signature;
   }

   public CertificateBody getBody() {
      return this.certificateBody;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (this.valid != (signValid | bodyValid)) {
         return null;
      } else {
         var1.add(this.certificateBody);

         try {
            var1.add(new DERApplicationSpecific(false, 55, new DEROctetString(this.signature)));
         } catch (IOException var3) {
            throw new IllegalStateException("unable to convert signature!");
         }

         return new DERApplicationSpecific(33, var1);
      }
   }

   public ASN1ObjectIdentifier getHolderAuthorization() throws IOException {
      CertificateHolderAuthorization var1 = this.certificateBody.getCertificateHolderAuthorization();
      return var1.getOid();
   }

   public PackedDate getEffectiveDate() throws IOException {
      return this.certificateBody.getCertificateEffectiveDate();
   }

   public int getCertificateType() {
      return this.certificateBody.getCertificateType();
   }

   public PackedDate getExpirationDate() throws IOException {
      return this.certificateBody.getCertificateExpirationDate();
   }

   public int getRole() throws IOException {
      CertificateHolderAuthorization var1 = this.certificateBody.getCertificateHolderAuthorization();
      return var1.getAccessRights();
   }

   public CertificationAuthorityReference getAuthorityReference() throws IOException {
      return this.certificateBody.getCertificationAuthorityReference();
   }

   public CertificateHolderReference getHolderReference() throws IOException {
      return this.certificateBody.getCertificateHolderReference();
   }

   public int getHolderAuthorizationRole() throws IOException {
      int var1 = this.certificateBody.getCertificateHolderAuthorization().getAccessRights();
      return var1 & 192;
   }

   public Flags getHolderAuthorizationRights() throws IOException {
      return new Flags(this.certificateBody.getCertificateHolderAuthorization().getAccessRights() & 31);
   }
}
