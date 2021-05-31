package org.bc.jce.provider;

import java.io.OutputStream;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;

public class JDKPKCS12StoreParameter implements LoadStoreParameter {
   private OutputStream outputStream;
   private ProtectionParameter protectionParameter;
   private boolean useDEREncoding;

   public OutputStream getOutputStream() {
      return this.outputStream;
   }

   public ProtectionParameter getProtectionParameter() {
      return this.protectionParameter;
   }

   public boolean isUseDEREncoding() {
      return this.useDEREncoding;
   }

   public void setOutputStream(OutputStream var1) {
      this.outputStream = var1;
   }

   public void setPassword(char[] var1) {
      this.protectionParameter = new PasswordProtection(var1);
   }

   public void setProtectionParameter(ProtectionParameter var1) {
      this.protectionParameter = var1;
   }

   public void setUseDEREncoding(boolean var1) {
      this.useDEREncoding = var1;
   }
}
