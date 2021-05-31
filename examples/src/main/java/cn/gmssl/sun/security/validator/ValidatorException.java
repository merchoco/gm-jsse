package cn.gmssl.sun.security.validator;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class ValidatorException extends CertificateException {
   private static final long serialVersionUID = -2836879718282292155L;
   public static final Object T_NO_TRUST_ANCHOR = "No trusted certificate found";
   public static final Object T_EE_EXTENSIONS = "End entity certificate extension check failed";
   public static final Object T_CA_EXTENSIONS = "CA certificate extension check failed";
   public static final Object T_CERT_EXPIRED = "Certificate expired";
   public static final Object T_SIGNATURE_ERROR = "Certificate signature validation failed";
   public static final Object T_NAME_CHAINING = "Certificate chaining error";
   public static final Object T_ALGORITHM_DISABLED = "Certificate signature algorithm disabled";
   private Object type;
   private X509Certificate cert;

   public ValidatorException(String var1) {
      super(var1);
   }

   public ValidatorException(String var1, Throwable var2) {
      super(var1);
      this.initCause(var2);
   }

   public ValidatorException(Object var1) {
      this((Object)var1, (X509Certificate)null);
   }

   public ValidatorException(Object var1, X509Certificate var2) {
      super((String)var1);
      this.type = var1;
      this.cert = var2;
   }

   public ValidatorException(Object var1, X509Certificate var2, Throwable var3) {
      this(var1, var2);
      this.initCause(var3);
   }

   public ValidatorException(String var1, Object var2, X509Certificate var3) {
      super(var1);
      this.type = var2;
      this.cert = var3;
   }

   public ValidatorException(String var1, Object var2, X509Certificate var3, Throwable var4) {
      this(var1, var2, var3);
      this.initCause(var4);
   }

   public Object getErrorType() {
      return this.type;
   }

   public X509Certificate getErrorCertificate() {
      return this.cert;
   }
}
