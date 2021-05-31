package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

public final class SSLServerSocketImpl extends SSLServerSocket {
   private SSLContextImpl sslContext;
   private byte doClientAuth = 0;
   private boolean useServerMode = true;
   private boolean enableSessionCreation = true;
   private CipherSuiteList enabledCipherSuites = null;
   private ProtocolList enabledProtocols = null;
   private boolean checkedEnabled = false;
   private String identificationProtocol = null;
   private AlgorithmConstraints algorithmConstraints = null;

   SSLServerSocketImpl(int var1, int var2, SSLContextImpl var3) throws IOException, SSLException {
      super(var1, var2);
      this.initServer(var3);
   }

   SSLServerSocketImpl(int var1, int var2, InetAddress var3, SSLContextImpl var4) throws IOException {
      super(var1, var2, var3);
      this.initServer(var4);
   }

   SSLServerSocketImpl(SSLContextImpl var1) throws IOException {
      this.initServer(var1);
   }

   private void initServer(SSLContextImpl var1) throws SSLException {
      if (var1 == null) {
         throw new SSLException("No Authentication context given");
      } else {
         this.sslContext = var1;
         this.enabledCipherSuites = this.sslContext.getDefaultCipherSuiteList(true);
         this.enabledProtocols = this.sslContext.getDefaultProtocolList(true);
      }
   }

   public String[] getSupportedCipherSuites() {
      return this.sslContext.getSuportedCipherSuiteList().toStringArray();
   }

   public synchronized String[] getEnabledCipherSuites() {
      return this.enabledCipherSuites.toStringArray();
   }

   public synchronized void setEnabledCipherSuites(String[] var1) {
      this.enabledCipherSuites = new CipherSuiteList(var1);
      this.checkedEnabled = false;
   }

   public String[] getSupportedProtocols() {
      return this.sslContext.getSuportedProtocolList().toStringArray();
   }

   public synchronized void setEnabledProtocols(String[] var1) {
      this.enabledProtocols = new ProtocolList(var1);
   }

   public synchronized String[] getEnabledProtocols() {
      return this.enabledProtocols.toStringArray();
   }

   public void setNeedClientAuth(boolean var1) {
      this.doClientAuth = (byte)(var1 ? 2 : 0);
   }

   public boolean getNeedClientAuth() {
      return this.doClientAuth == 2;
   }

   public void setWantClientAuth(boolean var1) {
      this.doClientAuth = (byte)(var1 ? 1 : 0);
   }

   public boolean getWantClientAuth() {
      return this.doClientAuth == 1;
   }

   public void setUseClientMode(boolean var1) {
      if (this.useServerMode != !var1 && this.sslContext.isDefaultProtocolList(this.enabledProtocols)) {
         this.enabledProtocols = this.sslContext.getDefaultProtocolList(!var1);
      }

      this.useServerMode = !var1;
   }

   public boolean getUseClientMode() {
      return !this.useServerMode;
   }

   public void setEnableSessionCreation(boolean var1) {
      this.enableSessionCreation = var1;
   }

   public boolean getEnableSessionCreation() {
      return this.enableSessionCreation;
   }

   public synchronized SSLParameters getSSLParameters() {
      SSLParameters var1 = super.getSSLParameters();
      var1.setEndpointIdentificationAlgorithm(this.identificationProtocol);
      var1.setAlgorithmConstraints(this.algorithmConstraints);
      return var1;
   }

   public synchronized void setSSLParameters(SSLParameters var1) {
      super.setSSLParameters(var1);
      this.identificationProtocol = var1.getEndpointIdentificationAlgorithm();
      this.algorithmConstraints = var1.getAlgorithmConstraints();
   }

   public Socket accept() throws IOException {
      SSLSocketImpl var1 = new SSLSocketImpl(this.sslContext, this.useServerMode, this.enabledCipherSuites, this.doClientAuth, this.enableSessionCreation, this.enabledProtocols, this.identificationProtocol, this.algorithmConstraints);
      this.implAccept(var1);
      var1.doneConnect();
      return var1;
   }

   public String toString() {
      return "[SSL: " + super.toString() + "]";
   }
}
