package com.aliyun.gmsse.record;

import com.aliyun.gmsse.*;
import com.aliyun.gmsse.handshake.Certificate;
import com.aliyun.gmsse.handshake.CertificateRequest;
import com.aliyun.gmsse.handshake.ClientHello;
import com.aliyun.gmsse.handshake.ServerHello;
import test.CertUtils;

import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class ServerHandshaker extends Handshake {
    public ServerHandshaker(Type type, Body body) {
        super(type, body);
    }

    public ServerHandshaker() {
    }

    public ServerHandshaker(GMSSLSocket gmsslSocket) {
        super(gmsslSocket);
    }

    public void startHandshake(Record record) {
        //

        try {
            shake(record);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void shake(Record record) throws Exception {
        record.print(System.out);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(record.fragment);

        Handshake read = read(inputStream);
    }

    private void clientHello(ClientHello clientHello) {
        List<CipherSuite> suites = clientHello.getSuites();
    }

    /**
     * @param clientHello
     */
    public void client(ClientHello clientHello) {

        //构造serverHello
        ServerHello serverHello = new ServerHello();
        List<CipherSuite> suites = clientHello.getSuites();
        ProtocolVersion clientRequestedVersion = clientHello.getVersion();
        ProtocolVersion protocolVersion =
                ProtocolVersion.getInstance(clientRequestedVersion.getMajor(), clientRequestedVersion.getMinor());

        //设置版本
        serverHello.setVersion(protocolVersion);
        //设置随机数
        ClientRandom serRandom = new ClientRandom(new SecureRandom());
        serverHello.setRandom(serRandom.getBytes());
        GMSSLSession session = new GMSSLSession(suites, Arrays.asList(protocolVersion));

        //设置sessionId
        serverHello.setSessionId(serRandom.getBytes());

        //设置选中的加密套件
        serverHello.setSuite(CipherSuite.NTLS_SM2_WITH_SM4_SM3);
        //支持的压缩算法
        serverHello.setCompression(CompressionMethod.getInstance(0));

        RecordStream recordStream = conn.getRecordStream();
        byte[] serverHelloBytes = new byte[0];
        try {
            serverHelloBytes = serverHello.getBytes();
            //构造握手协议：
            byte[] bytes = new byte[1 + 3 + serverHelloBytes.length];
            bytes[0] = 0x02;

            bytes[1] = (byte) (serverHelloBytes.length >> 16);
            bytes[2] = (byte) (serverHelloBytes.length >> 8);
            bytes[3] = (byte) (serverHelloBytes.length >> 0);

            System.arraycopy(serverHelloBytes, 0, bytes, 4, serverHelloBytes.length);
            Record record = new Record(Record.ContentType.HANDSHAKE, protocolVersion, bytes);
            System.out.println("++++serverHello :");
            record.print(System.out);

            //构造记录协议并发送
            recordStream.write(record);
        } catch (IOException e) {
            e.printStackTrace();
        }
        X509Certificate[] certs = new X509Certificate[4];
        //var25[0] = this.certs[0];
        //var25[1] = this.encCerts[0];

       // X509ExtendedKeyManager keyManager = this.sslContext.getX509KeyManager();
        //aliax = keyManager.chooseServerAlias(algorithm, (Principal[])null, this.conn);
     /*   String var14 = aliax.substring(0, var4);
        String var15 = aliax.substring(var4 + 1);
        X509Certificate[] var18 = keyManager.getCertificateChain(var14);
        X509Certificate[] var19 = keyManager.getCertificateChain(var15);
        PrivateKey var17 = keyManager.getPrivateKey(var15);
        PrivateKey var16 = keyManager.getPrivateKey(var14);
         encPrivateKey = var17;
         encCerts = var19;
         privateKey = var16;
         certs = var18;
        certs[0] = this.vr18[0];
        certs[1] = this.var19[0];

        for(int i = 0; i < this.certs.length - 1; ++i) {
            certs[2 + i] = this.certs[1 + i];
        }*/

        Certificate certificate = new Certificate(CertUtils.getCert());
        //构造握手协议

    }
}
