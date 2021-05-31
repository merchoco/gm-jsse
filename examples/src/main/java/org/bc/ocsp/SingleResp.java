package org.bc.ocsp;

import java.security.cert.X509Extension;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.ocsp.CertStatus;
import org.bc.asn1.ocsp.RevokedInfo;
import org.bc.asn1.ocsp.SingleResponse;
import org.bc.asn1.x509.X509Extensions;

public class SingleResp implements X509Extension {
   SingleResponse resp;

   public SingleResp(SingleResponse var1) {
      this.resp = var1;
   }

   public CertificateID getCertID() {
      return new CertificateID(this.resp.getCertID());
   }

   public Object getCertStatus() {
      CertStatus var1 = this.resp.getCertStatus();
      if (var1.getTagNo() == 0) {
         return null;
      } else {
         return var1.getTagNo() == 1 ? new RevokedStatus(RevokedInfo.getInstance(var1.getStatus())) : new UnknownStatus();
      }
   }

   public Date getThisUpdate() {
      try {
         return this.resp.getThisUpdate().getDate();
      } catch (ParseException var2) {
         throw new IllegalStateException("ParseException: " + var2.getMessage());
      }
   }

   public Date getNextUpdate() {
      if (this.resp.getNextUpdate() == null) {
         return null;
      } else {
         try {
            return this.resp.getNextUpdate().getDate();
         } catch (ParseException var2) {
            throw new IllegalStateException("ParseException: " + var2.getMessage());
         }
      }
   }

   public X509Extensions getSingleExtensions() {
      return X509Extensions.getInstance(this.resp.getSingleExtensions());
   }

   public boolean hasUnsupportedCriticalExtension() {
      Set var1 = this.getCriticalExtensionOIDs();
      return var1 != null && !var1.isEmpty();
   }

   private Set getExtensionOIDs(boolean var1) {
      HashSet var2 = new HashSet();
      X509Extensions var3 = this.getSingleExtensions();
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
      X509Extensions var2 = this.getSingleExtensions();
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
}
