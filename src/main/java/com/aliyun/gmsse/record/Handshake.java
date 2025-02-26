package com.aliyun.gmsse.record;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.List;

import com.aliyun.gmsse.CipherSuite;
import com.aliyun.gmsse.GMSSLSocket;
import com.aliyun.gmsse.ProtocolVersion;
import com.aliyun.gmsse.handshake.Certificate;
import com.aliyun.gmsse.handshake.CertificateRequest;
import com.aliyun.gmsse.handshake.CertificateVerify;
import com.aliyun.gmsse.handshake.ClientHello;
import com.aliyun.gmsse.handshake.ClientKeyExchange;
import com.aliyun.gmsse.handshake.Finished;
import com.aliyun.gmsse.handshake.ServerHello;
import com.aliyun.gmsse.handshake.ServerHelloDone;
import com.aliyun.gmsse.handshake.ServerKeyExchange;

/**
 * 握手
 */
public class Handshake implements RecordFragment {
    static GMSSLSocket conn = null;
    public Type type;
    public Body body;
    private int status = 0;

    public Handshake() {
    }

    public Handshake(Type type, Body body) {
        this.type = type;
        this.body = body;
    }

    public Handshake(GMSSLSocket gmsslSocket) {
        this.conn=gmsslSocket;
    }

    public void startHandshake() {

    }

    public boolean isDone() {
        return status ==1 ;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public void startHandshake(Record record) {
    }

    public static class Type {
        public static final Type CLIENT_HELLO = new Type(1);
        public static final Type SERVER_HELLO = new Type(2);
        public static final Type CERTIFICATE = new Type(11);
        public static final Type SERVER_KEY_EXCHANGE = new Type(12);
        public static final Type CERTIFICATE_REQUEST = new Type(13);
        public static final Type SERVER_HELLO_DONE = new Type(14);
        public static final Type CERTIFICATE_VERIFY = new Type(15);
        public static final Type CLIENT_KEY_EXCHANGE = new Type(16);
        public static final Type FINISHED = new Type(20);

        final private int value;

        public Type(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static Type getInstance(int type) {
            switch (type) {
                case 1:
                    return CLIENT_HELLO;
                case 2:
                    return SERVER_HELLO;
                case 11:
                    return CERTIFICATE;
                case 12:
                    return SERVER_KEY_EXCHANGE;
                case 13:
                    return CERTIFICATE_REQUEST;
                case 14:
                    return SERVER_HELLO_DONE;
                case 15:
                    return CERTIFICATE_VERIFY;
                case 16:
                    return CLIENT_KEY_EXCHANGE;
                case 20:
                    return FINISHED;
                default:
                    break;
            }
            return null;
        }
    }

    public static abstract class Body {
        public abstract byte[] getBytes() throws IOException;

        public  abstract void print(PrintStream out);

       
    }

    
    public  Handshake  read(InputStream input) throws IOException {
        // type
        int type = input.read() & 0xFF;
        //
        int msgLength = (input.read() & 0xFF) << 16 | (input.read() & 0xFF) << 8 | (input.read() & 0xFF);
       //
        Handshake.Body body = null;
        switch (type) {
            case 0x01:
                body = ClientHello.read(input);
                System.out.println("++++clientHello: ");
                body.print(System.out);
                client((ClientHello) body);;
                break;
            case 0x02:
                body = ServerHello.read(input);
                break;
            case 0x0b:
                body = Certificate.read(input);
                break;
            case 0x0c:
                body = ServerKeyExchange.read(input);
                break;
            case 0x0d:
                body = CertificateRequest.read(input);
                break;
            case 0x0e:
                body = ServerHelloDone.read(input);
                break;
            case 0x0f:
                body = CertificateVerify.read(input);
                break;
            case 0x10:
                body = ClientKeyExchange.read(input);
                break;
            case 0x14:
                body = Finished.read(input, msgLength);
                break;
            default:
                break;
        }
        return new Handshake(Type.getInstance(type), body);
    }

    public void client(ClientHello body) {
        //serverHello
       // List<CipherSuite> suites = body.getSuites();

      //  ServerHello serverHello = new ServerHello();
      //  serverHello.setVersion(ProtocolVersion.NTLS_1_1);
        //serverHello.setRandom(new R);
        //serverHello.setSuite();

    }


    public byte[] getBytes() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        // handshake type
        os.write(type.getValue());
        byte[] bytes = body.getBytes();
        // handshake body length
        os.write(bytes.length >>> 16 & 0xFF);
        os.write(bytes.length >>> 8 & 0xFF);
        os.write(bytes.length & 0xFF);
        // handshake body
        os.write(bytes);
        return os.toByteArray();
    }
}
