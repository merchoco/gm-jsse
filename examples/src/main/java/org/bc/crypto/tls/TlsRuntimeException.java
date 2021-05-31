package org.bc.crypto.tls;

public class TlsRuntimeException extends RuntimeException {
   private static final long serialVersionUID = 1928023487348344086L;
   Throwable e;

   public TlsRuntimeException(String var1, Throwable var2) {
      super(var1);
      this.e = var2;
   }

   public TlsRuntimeException(String var1) {
      super(var1);
   }

   public Throwable getCause() {
      return this.e;
   }
}
