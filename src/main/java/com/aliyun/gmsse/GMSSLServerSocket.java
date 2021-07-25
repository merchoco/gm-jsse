package com.aliyun.gmsse;

import sun.security.ssl.SSLContextImpl;
import sun.security.ssl.SSLSocketImpl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.util.List;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

public final class GMSSLServerSocket extends SSLServerSocket {
    private SSLContextImpl sslContext;
    private byte doClientAuth = 0;
    private boolean useServerMode = true;
    private boolean enableSessionCreation = true;
    private List<CipherSuite> enabledCipherSuites = null;
    private List<ProtocolVersion> enabledProtocol= null;
    private boolean checkedEnabled = false;
    private String identificationProtocol = null;
    private AlgorithmConstraints algorithmConstraints = null;

    GMSSLServerSocket(int port, int backlog, SSLContextImpl context) throws IOException, SSLException {
        super(port, backlog);
        this.initServer(context);
    }

    GMSSLServerSocket(int port, int backlog, InetAddress address, SSLContextImpl context) throws IOException {
        super(port, backlog, address);
        this.initServer(context);
    }

    GMSSLServerSocket(SSLContextImpl context) throws IOException {
        super();
        initServer(context);
    }
    GMSSLServerSocket(GMSSLContextSpi context) throws IOException {
        super();
        initServer(context);
    }
    GMSSLServerSocket(int port,GMSSLContextSpi context) throws IOException {
        super(port);
        initServer(context);
    }


    private void initServer(SSLContextImpl var1) throws SSLException {
        if (var1 == null) {
            throw new SSLException("No Authentication context given");
        } else {
            this.sslContext = var1;
           // this.enabledCipherSuites = this.sslContext.getDefaultCipherSuiteList(true);
           // this.enabledProtocols = this.sslContext.getDefaultProtocolList(true);
        }
    }
    private void initServer(GMSSLContextSpi var1) throws SSLException {
        if (var1 == null) {
            throw new SSLException("No Authentication context given");
        } else {
           // this.sslContext = var1;
           // this.enabledCipherSuites = this.sslContext.getDefaultCipherSuiteList(true);
           // this.enabledProtocols = this.sslContext.getDefaultProtocolList(true);
        }
    }

    public String[] getSupportedCipherSuites() {
        //return this.sslContext.getSuportedCipherSuiteList().toStringArray();
        return null;
    }

    public synchronized String[] getEnabledCipherSuites() {
        //return this.enabledCipherSuites.toStringArray();
        return null;

    }

    public synchronized void setEnabledCipherSuites(String[] var1) {
       // this.enabledCipherSuites = new CipherSuiteList(var1);
        this.checkedEnabled = false;
    }

    public String[] getSupportedProtocols() {
        //return this.sslContext.getSuportedProtocolList().toStringArray();
        return null;
    }

    public synchronized void setEnabledProtocols(String[] var1) {
       // this.enabledProtocols = new ProtocolList(var1);

    }

    public synchronized String[] getEnabledProtocols() {
      //  return this.enabledProtocols.toStringArray();
        return null;
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
       /* if (this.useServerMode != !var1 && this.sslContext.isDefaultProtocolList(this.enabledProtocols)) {
            this.enabledProtocols = this.sslContext.getDefaultProtocolList(!var1);
        }*/

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
        GMSSLSocket gmsslSocket = new GMSSLSocket(true);
        this.implAccept(gmsslSocket);
        gmsslSocket.doneConnect();
        return gmsslSocket;
    }

    public String toString() {
        return "[SSL: " + super.toString() + "]";
    }
}
