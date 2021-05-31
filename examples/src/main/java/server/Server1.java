package server;

import java.net.*;
import java.io.*;
import java.security.*;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import client.TrustAllManager;
import cn.gmssl.sun.security.ssl.SunX509KeyManagerImpl;

public class Server1
{
	public Server1()
	{}

	public static void main(String[] args) throws Exception {
		ServerSocketFactory fact = null;
		SSLServerSocket serversocket = null;
		int port = 8441;
		String pwdpwd = "12345678";

		Security.insertProviderAt(new cn.gmssl.jce.provider.GMJCE(), 1);
		Security.insertProviderAt(new cn.gmssl.jsse.provider.GMJSSE(), 2);
		KeyStore pfx = KeyStore.getInstance("PKCS12", "GMJSSE");
		pfx.load(new FileInputStream("D:\\dev\\dev2\\gm-jsse\\examples\\src\\main\\resources\\keystore\\sm2.server1.both.pfx"), pwdpwd.toCharArray());

		fact = createServerSocketFactory(pfx, pwdpwd.toCharArray());
		serversocket = (SSLServerSocket) fact.createServerSocket(port);

		while (true)
		{
			Socket socket = null;
			try
			{
				socket = serversocket.accept();

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

	public static SSLServerSocketFactory createServerSocketFactory(KeyStore kepair, char[] pwd) throws Exception
	{
		TrustManager[] trust = { new TrustAllManager() };
		SunX509KeyManagerImpl keyManager = new SunX509KeyManagerImpl(kepair, pwd);

		SSLContext ctx = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
		java.security.SecureRandom secureRandom = new java.security.SecureRandom();

		ctx.init(new KeyManager[]{keyManager}, trust, secureRandom);

		ctx.getServerSessionContext().setSessionCacheSize(8192);
		ctx.getServerSessionContext().setSessionTimeout(3600);

		SSLServerSocketFactory factory = ctx.getServerSocketFactory();
		return factory;
	}
}
