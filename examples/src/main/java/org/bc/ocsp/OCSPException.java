package org.bc.ocsp;

public class OCSPException extends Exception {
   Exception e;

   public OCSPException(String var1) {
      super(var1);
   }

   public OCSPException(String var1, Exception var2) {
      super(var1);
      this.e = var2;
   }

   public Exception getUnderlyingException() {
      return this.e;
   }

   public Throwable getCause() {
      return this.e;
   }
}
