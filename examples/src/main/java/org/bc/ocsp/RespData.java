package org.bc.ocsp;

import java.security.cert.X509Extension;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.ocsp.ResponseData;
import org.bc.asn1.ocsp.SingleResponse;
import org.bc.asn1.x509.X509Extensions;

public class RespData implements X509Extension {
   ResponseData data;

   public RespData(ResponseData var1) {
      this.data = var1;
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
}
