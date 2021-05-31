package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import javax.net.ssl.SSLSocket;

abstract class BaseSSLSocketImpl extends SSLSocket {
   final Socket self;
   private static final String PROP_NAME = "com.sun.net.ssl.requireCloseNotify";
   static final boolean requireCloseNotify = Debug.getBooleanProperty("com.sun.net.ssl.requireCloseNotify", false);

   BaseSSLSocketImpl() {
      this.self = this;
   }

   BaseSSLSocketImpl(Socket var1) {
      this.self = var1;
   }

   public final SocketChannel getChannel() {
      return this.self == this ? super.getChannel() : this.self.getChannel();
   }

   public void bind(SocketAddress var1) throws IOException {
      if (this.self == this) {
         super.bind(var1);
      } else {
         throw new IOException("Underlying socket should already be connected");
      }
   }

   public SocketAddress getLocalSocketAddress() {
      return this.self == this ? super.getLocalSocketAddress() : this.self.getLocalSocketAddress();
   }

   public SocketAddress getRemoteSocketAddress() {
      return this.self == this ? super.getRemoteSocketAddress() : this.self.getRemoteSocketAddress();
   }

   public final void connect(SocketAddress var1) throws IOException {
      this.connect(var1, 0);
   }

   public final boolean isConnected() {
      return this.self == this ? super.isConnected() : this.self.isConnected();
   }

   public final boolean isBound() {
      return this.self == this ? super.isBound() : this.self.isBound();
   }

   public final void shutdownInput() throws IOException {
      throw new UnsupportedOperationException("The method shutdownInput() is not supported in SSLSocket");
   }

   public final void shutdownOutput() throws IOException {
      throw new UnsupportedOperationException("The method shutdownOutput() is not supported in SSLSocket");
   }

   public final boolean isInputShutdown() {
      return this.self == this ? super.isInputShutdown() : this.self.isInputShutdown();
   }

   public final boolean isOutputShutdown() {
      return this.self == this ? super.isOutputShutdown() : this.self.isOutputShutdown();
   }

   protected final void finalize() throws Throwable {
      try {
         this.close();
      } catch (IOException var8) {
         try {
            if (this.self == this) {
               super.close();
            }
         } catch (IOException var7) {
            ;
         }
      } finally {
         super.finalize();
      }

   }

   public final InetAddress getInetAddress() {
      return this.self == this ? super.getInetAddress() : this.self.getInetAddress();
   }

   public final InetAddress getLocalAddress() {
      return this.self == this ? super.getLocalAddress() : this.self.getLocalAddress();
   }

   public final int getPort() {
      return this.self == this ? super.getPort() : this.self.getPort();
   }

   public final int getLocalPort() {
      return this.self == this ? super.getLocalPort() : this.self.getLocalPort();
   }

   public final void setTcpNoDelay(boolean var1) throws SocketException {
      if (this.self == this) {
         super.setTcpNoDelay(var1);
      } else {
         this.self.setTcpNoDelay(var1);
      }

   }

   public final boolean getTcpNoDelay() throws SocketException {
      return this.self == this ? super.getTcpNoDelay() : this.self.getTcpNoDelay();
   }

   public final void setSoLinger(boolean var1, int var2) throws SocketException {
      if (this.self == this) {
         super.setSoLinger(var1, var2);
      } else {
         this.self.setSoLinger(var1, var2);
      }

   }

   public final int getSoLinger() throws SocketException {
      return this.self == this ? super.getSoLinger() : this.self.getSoLinger();
   }

   public final void sendUrgentData(int var1) throws SocketException {
      throw new SocketException("This method is not supported by SSLSockets");
   }

   public final void setOOBInline(boolean var1) throws SocketException {
      throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
   }

   public final boolean getOOBInline() throws SocketException {
      throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
   }

   public final int getSoTimeout() throws SocketException {
      return this.self == this ? super.getSoTimeout() : this.self.getSoTimeout();
   }

   public final void setSendBufferSize(int var1) throws SocketException {
      if (this.self == this) {
         super.setSendBufferSize(var1);
      } else {
         this.self.setSendBufferSize(var1);
      }

   }

   public final int getSendBufferSize() throws SocketException {
      return this.self == this ? super.getSendBufferSize() : this.self.getSendBufferSize();
   }

   public final void setReceiveBufferSize(int var1) throws SocketException {
      if (this.self == this) {
         super.setReceiveBufferSize(var1);
      } else {
         this.self.setReceiveBufferSize(var1);
      }

   }

   public final int getReceiveBufferSize() throws SocketException {
      return this.self == this ? super.getReceiveBufferSize() : this.self.getReceiveBufferSize();
   }

   public final void setKeepAlive(boolean var1) throws SocketException {
      if (this.self == this) {
         super.setKeepAlive(var1);
      } else {
         this.self.setKeepAlive(var1);
      }

   }

   public final boolean getKeepAlive() throws SocketException {
      return this.self == this ? super.getKeepAlive() : this.self.getKeepAlive();
   }

   public final void setTrafficClass(int var1) throws SocketException {
      if (this.self == this) {
         super.setTrafficClass(var1);
      } else {
         this.self.setTrafficClass(var1);
      }

   }

   public final int getTrafficClass() throws SocketException {
      return this.self == this ? super.getTrafficClass() : this.self.getTrafficClass();
   }

   public final void setReuseAddress(boolean var1) throws SocketException {
      if (this.self == this) {
         super.setReuseAddress(var1);
      } else {
         this.self.setReuseAddress(var1);
      }

   }

   public final boolean getReuseAddress() throws SocketException {
      return this.self == this ? super.getReuseAddress() : this.self.getReuseAddress();
   }

   public void setPerformancePreferences(int var1, int var2, int var3) {
      if (this.self == this) {
         super.setPerformancePreferences(var1, var2, var3);
      } else {
         this.self.setPerformancePreferences(var1, var2, var3);
      }

   }
}
