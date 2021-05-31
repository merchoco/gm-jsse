package test;

import com.aliyun.gmsse.*;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Security;
import java.util.Enumeration;

public class GMServer {
	public GMServer() {
	}

	public static void main(String[] args) throws Exception {

		int port =8999;
		GMProvider provider = new GMProvider();
		KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
		keyStore.load(new FileInputStream(
				"D:\\dev\\dev2\\gm-jsse\\examples\\src\\main\\resources\\keystore\\sm2.server1.both.pfx"),
				"12345678".toCharArray());


		SunX509KeyManagerImpl keyManager = new SunX509KeyManagerImpl(keyStore,"12345678".toCharArray());

		SSLContext ctx = SSLContext.getInstance("TLS", provider);
		java.security.SecureRandom secureRandom = new java.security.SecureRandom();
		ctx.init(
				new KeyManager[]{keyManager},
				new TrustManager[]{new TrustAllManager()},
				secureRandom);

		//ctx.getServerSessionContext().setSessionCacheSize(8192);
		//ctx.getServerSessionContext().setSessionTimeout(3600);


		//SSLServerSocketFactory factory = ctx.getServerSocketFactory();


		//String[] defaultCipherSuites = factory.getDefaultCipherSuites();

		//Security.setProperty("ssl.ServerSocketFactory.provider",GMSSLServerSocketFactory.class.getName());
		//new GMSSLServerSocketFactory();
		//ServerSocketFactory aDefault = SSLServerSocketFactory.getDefault();
		//SSLServerSocketFactory factory =RefectUtil.getServerSocketFactory(ctx);

		SSLServerSocketFactory socketFactory = ctx.getServerSocketFactory();
		ServerSocket serverSocket = socketFactory.createServerSocket(port);

		while (true)
		{
			Socket socket = null;
			try
			{
				socket = serverSocket.accept();

				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				byte[] buf = new byte[8192];
				int len = in.read(buf);
				if (len == -1)
				{
					System.out.println("eof");
				}
				System.out.println("****  request  from  client ...");
				System.out.println(new String(buf, 0, len));

				byte[] body = "this is a gm server".getBytes();
				byte[] resp = ("HTTP/1.1 200 OK\r\nServer: GMSSL/1.0\r\nContent-Length:"+body.length+"\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n").getBytes();
				out.write(resp, 0, resp.length);
				out.flush();
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
			finally
			{
				try
				{
					socket.close();
				}
				catch (Exception e)
				{}
			}
		}
	}

}
