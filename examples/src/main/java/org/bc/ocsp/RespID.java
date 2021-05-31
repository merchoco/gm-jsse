package org.bc.ocsp;

import java.security.MessageDigest;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.ocsp.ResponderID;
import org.bc.asn1.x500.X500Name;
import org.bc.asn1.x509.SubjectPublicKeyInfo;

public class RespID {
   ResponderID id;

   public RespID(ResponderID var1) {
      this.id = var1;
   }

   public RespID(X500Principal var1) {
      this.id = new ResponderID(X500Name.getInstance(var1.getEncoded()));
   }

   public RespID(PublicKey var1) throws OCSPException {
      try {
         MessageDigest var2 = OCSPUtil.createDigestInstance("SHA1", (String)null);
         ASN1InputStream var3 = new ASN1InputStream(var1.getEncoded());
         SubjectPublicKeyInfo var4 = SubjectPublicKeyInfo.getInstance(var3.readObject());
         var2.update(var4.getPublicKeyData().getBytes());
         DEROctetString var5 = new DEROctetString(var2.digest());
         this.id = new ResponderID(var5);
      } catch (Exception var6) {
         throw new OCSPException("problem creating ID: " + var6, var6);
      }
   }

   public ResponderID toASN1Object() {
      return this.id;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof RespID)) {
         return false;
      } else {
         RespID var2 = (RespID)var1;
         return this.id.equals(var2.id);
      }
   }

   public int hashCode() {
      return this.id.hashCode();
   }
}
