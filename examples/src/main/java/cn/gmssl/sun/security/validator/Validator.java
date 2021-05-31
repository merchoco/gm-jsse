package cn.gmssl.sun.security.validator;

import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

public abstract class Validator {
   static final X509Certificate[] CHAIN0 = new X509Certificate[0];
   public static final String TYPE_SIMPLE = "Simple";
   public static final String TYPE_PKIX = "PKIX";
   public static final String VAR_GENERIC = "generic";
   public static final String VAR_CODE_SIGNING = "code signing";
   public static final String VAR_JCE_SIGNING = "jce signing";
   public static final String VAR_TLS_CLIENT = "tls client";
   public static final String VAR_TLS_SERVER = "tls server";
   public static final String VAR_TSA_SERVER = "tsa server";
   public static final String VAR_PLUGIN_CODE_SIGNING = "plugin code signing";
   final EndEntityChecker endEntityChecker;
   final String variant;
   /** @deprecated */
   @Deprecated
   volatile Date validationDate;

   Validator(String var1, String var2) {
      this.variant = var2;
      this.endEntityChecker = EndEntityChecker.getInstance(var1, var2);
   }

   public static Validator getInstance(String var0, String var1, KeyStore var2) {
      return getInstance(var0, var1, (Collection)KeyStores.getTrustedCerts(var2));
   }

   public static Validator getInstance(String var0, String var1, Collection<X509Certificate> var2) {
      if (var0.equals("Simple")) {
         return new SimpleValidator(var1, var2);
      } else if (var0.equals("PKIX")) {
         return new PKIXValidator(var1, var2);
      } else {
         throw new IllegalArgumentException("Unknown validator type: " + var0);
      }
   }

   public static Validator getInstance(String var0, String var1, PKIXBuilderParameters var2) {
      if (!var0.equals("PKIX")) {
         throw new IllegalArgumentException("getInstance(PKIXBuilderParameters) can only be used with PKIX validator");
      } else {
         return new PKIXValidator(var1, var2);
      }
   }

   public final X509Certificate[] validate(X509Certificate[] var1) throws CertificateException {
      return this.validate(var1, (Collection)null, (Object)null);
   }

   public final X509Certificate[] validate(X509Certificate[] var1, Collection<X509Certificate> var2) throws CertificateException {
      return this.validate(var1, var2, (Object)null);
   }

   public final X509Certificate[] validate(X509Certificate[] var1, Collection<X509Certificate> var2, Object var3) throws CertificateException {
      return this.validate(var1, var2, (AlgorithmConstraints)null, var3);
   }

   public final X509Certificate[] validate(X509Certificate[] var1, Collection<X509Certificate> var2, AlgorithmConstraints var3, Object var4) throws CertificateException {
      var1 = this.engineValidate(var1, var2, var3, var4);
      if (var1.length > 1) {
         this.endEntityChecker.check(var1[0], var4);
      }

      return var1;
   }

   abstract X509Certificate[] engineValidate(X509Certificate[] var1, Collection<X509Certificate> var2, AlgorithmConstraints var3, Object var4) throws CertificateException;

   public abstract Collection<X509Certificate> getTrustedCertificates();

   /** @deprecated */
   @Deprecated
   public void setValidationDate(Date var1) {
      this.validationDate = var1;
   }
}
