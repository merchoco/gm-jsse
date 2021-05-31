/*
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import sun.security.ssl.SSLContextImpl.DefaultSSLContext;

public final class SSLServerSocketFactoryImpl extends SSLServerSocketFactory {
    private static final int DEFAULT_BACKLOG = 50;
    private final SSLContextImp context;

    public SSLServerSocketFactoryImpl() throws Exception {
        this.context = DefaultSSLContext.getDefaultImpl();
    }

    SSLServerSocketFactoryImpl(SSLContextImpl var1) {
        this.context = var1;
    }

    public ServerSocket createServerSocket() throws IOException {
        return new SSLServerSocketImpl(this.context);
    }

    public ServerSocket createServerSocket(int var1) throws IOException {
        return new SSLServerSocketImpl(this.context, var1, 50);
    }

    public ServerSocket createServerSocket(int var1, int var2) throws IOException {
        return new SSLServerSocketImpl(this.context, var1, var2);
    }

    public ServerSocket createServerSocket(int var1, int var2, InetAddress var3) throws IOException {
        return new SSLServerSocketImpl(this.context, var1, var2, var3);
    }

    public String[] getDefaultCipherSuites() {
        return CipherSuite.namesOf(this.context.getDefaultCipherSuites(true));
    }

    public String[] getSupportedCipherSuites() {
        return CipherSuite.namesOf(this.context.getSupportedCipherSuites());
    }
}
*/
