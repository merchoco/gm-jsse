package org.bc.jce.provider;

import org.bc.jce.exception.ExtException;

public class AnnotatedException extends Exception implements ExtException {
   private Throwable _underlyingException;

   AnnotatedException(String var1, Throwable var2) {
      super(var1);
      this._underlyingException = var2;
   }

   AnnotatedException(String var1) {
      this(var1, (Throwable)null);
   }

   Throwable getUnderlyingException() {
      return this._underlyingException;
   }

   public Throwable getCause() {
      return this._underlyingException;
   }
}
