package org.bc.crypto.tls;

import java.util.Vector;

public class CertificateRequest {
   private short[] certificateTypes;
   private Vector certificateAuthorities;

   public CertificateRequest(short[] var1, Vector var2) {
      this.certificateTypes = var1;
      this.certificateAuthorities = var2;
   }

   public short[] getCertificateTypes() {
      return this.certificateTypes;
   }

   public Vector getCertificateAuthorities() {
      return this.certificateAuthorities;
   }
}
