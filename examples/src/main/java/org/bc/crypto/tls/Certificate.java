package org.bc.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Primitive;

public class Certificate {
   public static final Certificate EMPTY_CHAIN = new Certificate(new org.bc.asn1.x509.Certificate[0]);
   protected org.bc.asn1.x509.Certificate[] certs;

   protected static Certificate parse(InputStream var0) throws IOException {
      int var2 = TlsUtils.readUint24(var0);
      if (var2 == 0) {
         return EMPTY_CHAIN;
      } else {
         Vector var3 = new Vector();

         int var4;
         while(var2 > 0) {
            var4 = TlsUtils.readUint24(var0);
            var2 -= 3 + var4;
            byte[] var5 = new byte[var4];
            TlsUtils.readFully(var5, var0);
            ByteArrayInputStream var6 = new ByteArrayInputStream(var5);
            ASN1InputStream var7 = new ASN1InputStream(var6);
            ASN1Primitive var8 = var7.readObject();
            var3.addElement(org.bc.asn1.x509.Certificate.getInstance(var8));
            if (var6.available() > 0) {
               throw new IllegalArgumentException("Sorry, there is garbage data left after the certificate");
            }
         }

         org.bc.asn1.x509.Certificate[] var1 = new org.bc.asn1.x509.Certificate[var3.size()];

         for(var4 = 0; var4 < var3.size(); ++var4) {
            var1[var4] = (org.bc.asn1.x509.Certificate)var3.elementAt(var4);
         }

         return new Certificate(var1);
      }
   }

   protected void encode(OutputStream var1) throws IOException {
      Vector var2 = new Vector();
      int var3 = 0;

      int var4;
      byte[] var5;
      for(var4 = 0; var4 < this.certs.length; ++var4) {
         var5 = this.certs[var4].getEncoded("DER");
         var2.addElement(var5);
         var3 += var5.length + 3;
      }

      TlsUtils.writeUint24(var3, var1);

      for(var4 = 0; var4 < var2.size(); ++var4) {
         var5 = (byte[])var2.elementAt(var4);
         TlsUtils.writeOpaque24(var5, var1);
      }

   }

   public Certificate(org.bc.asn1.x509.Certificate[] var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("'certs' cannot be null");
      } else {
         this.certs = var1;
      }
   }

   public org.bc.asn1.x509.Certificate[] getCerts() {
      org.bc.asn1.x509.Certificate[] var1 = new org.bc.asn1.x509.Certificate[this.certs.length];
      System.arraycopy(this.certs, 0, var1, 0, this.certs.length);
      return var1;
   }

   public boolean isEmpty() {
      return this.certs.length == 0;
   }
}
