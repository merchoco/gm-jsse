package test;

import com.aliyun.gmsse.GMProvider;
import com.aliyun.gmsse.GMSSLSocket;
import com.aliyun.gmsse.SunX509KeyManagerImpl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class GMServer {
    public GMServer() {
    }

    public static void main(String[] args) throws Exception {
        int port =8447;
        SSLServerSocketFactory socketFactory = CertUtils.getCtx().getServerSocketFactory();
        ServerSocket serverSocket = socketFactory.createServerSocket(port);
        GMSSLSocket socket = null;
        try {
            socket = (GMSSLSocket) serverSocket.accept();
            InputStream in = socket.getInputStream();
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            byte[] buf = new byte[8192];
            int len = in.read(buf);
            if (len == -1) {
                System.out.println("eof");
            }
            System.out.println("****  request  from  client ...");
            System.out.println(new String(buf, 0, len));
            byte[] body = "this is a message from gm server".getBytes();
            byte[] resp = ("HTTP/1.1 200 OK\r\nServer: GMSSL/1.0\r\nContent-Length:" + body.length + "\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n").getBytes();
            out.write(resp, 0, resp.length);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (Exception e) {
            }
        }

    }

}
