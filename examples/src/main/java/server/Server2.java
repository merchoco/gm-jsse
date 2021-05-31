package server;

import java.io.*;
import java.security.*;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

import client.TrustAllManager;

public class Server2
{
	public Server2()
	{}

	public static void main(String[] args) throws Exception
	{

		ServerSocketFactory fact = null;
		SSLServerSocket serversocket = null;
		int port = 8444;
		String pfxfile = "keystore/sm2.server1.both.pfx";
		String pwdpwd = "12345678";
		Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
		Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);
		KeyStore pfx = KeyStore.getInstance("PKCS12", "GMJSSE");
		pfx.load(Server2.class.getResourceAsStream(pfxfile), pwdpwd.toCharArray());
		fact = createServerSocketFactory(pfx, pwdpwd.toCharArray());
		serversocket = (SSLServerSocket) fact.createServerSocket(port);
		serversocket.setNeedClientAuth(false);
		serversocket.setWantClientAuth(false);
		while (true)
		{
			SSLSocket socket = null;
			try
			{
				socket = (SSLSocket)serversocket.accept();

				DataInputStream in = new DataInputStream(socket.getInputStream());
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());

				byte[] buf = new byte[8192];
				int len = in.read(buf);
				if (len == -1)
				{
					System.out.println("eof");
				}
				System.out.println(new String(buf, 0, len));
				
				byte[] body = "this is a gm server".getBytes();
				byte[] resp = ("HTTP/1.1 200 OK\r\nServer: GMSSL/1.0\r\nContent-Length:"+body.length+"\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n").getBytes();
				out.write(resp, 0, resp.length);
				out.flush();

				javax.security.cert.X509Certificate[] cs = socket.getSession().getPeerCertificateChain();
				System.out.println("client certs len=" + cs.length);
				for (int i = 0; i < cs.length; i++)
				{
					System.out.println(cs[i]);
				}
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

		KeyManager[] kms = null;
		if (kepair != null)
		{
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(kepair, pwd);
			kms = kmf.getKeyManagers();
		}

		SSLContext ctx = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
		java.security.SecureRandom secureRandom = new java.security.SecureRandom();
		ctx.init(kms, trust, secureRandom);
		
		ctx.getServerSessionContext().setSessionCacheSize(8192);
		ctx.getServerSessionContext().setSessionTimeout(3600);

		SSLServerSocketFactory factory = ctx.getServerSocketFactory();
		return factory;
	}
}
