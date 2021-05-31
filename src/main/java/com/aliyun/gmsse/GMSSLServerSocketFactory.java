//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.aliyun.gmsse;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

public  class GMSSLServerSocketFactory extends SSLServerSocketFactory {
    private static SSLServerSocketFactory theFactory;
    private static boolean propertyChecked;
    private  GMSSLContextSpi gmsslContextSpi;


    public GMSSLServerSocketFactory() {
    }

    public GMSSLServerSocketFactory(GMSSLContextSpi gmsslContextSpi) {
       this. gmsslContextSpi=gmsslContextSpi;
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException {

        return new GMSSLServerSocket(port,gmsslContextSpi);
    }

    @Override
    public ServerSocket createServerSocket(int i, int i1) throws IOException {
        return null;
    }

    @Override
    public ServerSocket createServerSocket(int i, int i1, InetAddress inetAddress) throws IOException {
        return null;
    }

    public  String[] getDefaultCipherSuites(){
        return null;
    };

    public  String[] getSupportedCipherSuites(){
        return  null;
    };
}
