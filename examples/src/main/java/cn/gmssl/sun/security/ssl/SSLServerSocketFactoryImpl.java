package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public final class SSLServerSocketFactoryImpl extends SSLServerSocketFactory {
   private static final int DEFAULT_BACKLOG = 50;
   private SSLContextImpl context;

   public SSLServerSocketFactoryImpl() throws Exception {
      this.context = SSLContextImpl.DefaultSSLContext.getDefaultImpl();
   }

   SSLServerSocketFactoryImpl(SSLContextImpl var1) {
      this.context = var1;
   }

   public ServerSocket createServerSocket() throws IOException {
      return new SSLServerSocketImpl(this.context);
   }

   public ServerSocket createServerSocket(int var1) throws IOException {
      return new SSLServerSocketImpl(var1, 50, this.context);
   }

   public ServerSocket createServerSocket(int var1, int var2) throws IOException {
      return new SSLServerSocketImpl(var1, var2, this.context);
   }

   public ServerSocket createServerSocket(int var1, int var2, InetAddress var3) throws IOException {
      return new SSLServerSocketImpl(var1, var2, var3, this.context);
   }

   public String[] getDefaultCipherSuites() {
      return this.context.getDefaultCipherSuiteList(true).toStringArray();
   }

   public String[] getSupportedCipherSuites() {
      return this.context.getSuportedCipherSuiteList().toStringArray();
   }
}
