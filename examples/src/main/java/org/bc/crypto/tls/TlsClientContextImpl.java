package org.bc.crypto.tls;

import java.security.SecureRandom;

class TlsClientContextImpl implements TlsClientContext {
   private SecureRandom secureRandom;
   private SecurityParameters securityParameters;
   private ProtocolVersion clientVersion = null;
   private ProtocolVersion serverVersion = null;
   private Object userObject = null;

   TlsClientContextImpl(SecureRandom var1, SecurityParameters var2) {
      this.secureRandom = var1;
      this.securityParameters = var2;
   }

   public SecureRandom getSecureRandom() {
      return this.secureRandom;
   }

   public SecurityParameters getSecurityParameters() {
      return this.securityParameters;
   }

   public ProtocolVersion getClientVersion() {
      return this.clientVersion;
   }

   public void setClientVersion(ProtocolVersion var1) {
      this.clientVersion = var1;
   }

   public ProtocolVersion getServerVersion() {
      return this.serverVersion;
   }

   public void setServerVersion(ProtocolVersion var1) {
      this.serverVersion = var1;
   }

   public Object getUserObject() {
      return this.userObject;
   }

   public void setUserObject(Object var1) {
      this.userObject = var1;
   }
}
