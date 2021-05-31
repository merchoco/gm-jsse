package org.bc.ocsp;

import java.text.ParseException;
import java.util.Date;
import org.bc.asn1.ASN1GeneralizedTime;
import org.bc.asn1.ocsp.RevokedInfo;
import org.bc.asn1.x509.CRLReason;

public class RevokedStatus implements CertificateStatus {
   RevokedInfo info;

   public RevokedStatus(RevokedInfo var1) {
      this.info = var1;
   }

   public RevokedStatus(Date var1, int var2) {
      this.info = new RevokedInfo(new ASN1GeneralizedTime(var1), CRLReason.lookup(var2));
   }

   public Date getRevocationTime() {
      try {
         return this.info.getRevocationTime().getDate();
      } catch (ParseException var2) {
         throw new IllegalStateException("ParseException:" + var2.getMessage());
      }
   }

   public boolean hasRevocationReason() {
      return this.info.getRevocationReason() != null;
   }

   public int getRevocationReason() {
      if (this.info.getRevocationReason() == null) {
         throw new IllegalStateException("attempt to get a reason where none is available");
      } else {
         return this.info.getRevocationReason().getValue().intValue();
      }
   }
}
