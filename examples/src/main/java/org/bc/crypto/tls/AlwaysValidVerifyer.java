package org.bc.crypto.tls;

/** @deprecated */
public class AlwaysValidVerifyer implements CertificateVerifyer {
   public boolean isValid(org.bc.asn1.x509.Certificate[] var1) {
      return true;
   }
}
