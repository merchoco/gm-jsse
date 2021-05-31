package client;

import java.net.*;
import java.io.*;
import java.security.*;

import javax.net.SocketFactory;
import javax.net.ssl.*;

public class Client2
{
	public Client2()
	{}

	public static void main(String[] args)
	{
		SocketFactory fact = null;
		SSLSocket socket = null;

		System.out.println("Usage: java -cp GMExample.jar client.Client2 addr port");
		
		try
		{
			String addr = "localhost";
			int port = 8444;
        	String uri = "/";
        	if(args.length > 0)
        	{
        		addr = args[0];
        		port = Integer.parseInt(args[1]);
        	}
        	
			Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
			Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

        	String pfxfile = "keystore/sm2.user1.both.pfx";
			String pwd = "12345678";
        	KeyStore pfx = KeyStore.getInstance("PKCS12","GMJCE");
        	pfx.load(Client2.class.getResourceAsStream(pfxfile), pwd.toCharArray());
			fact = createSocketFactory(pfx, pwd.toCharArray());
			socket = (SSLSocket) fact.createSocket();
    		socket.setEnabledCipherSuites(new String[] {"ECC_SM4_SM3"});
			socket.setTcpNoDelay(true);

			socket.connect(new InetSocketAddress(addr, port), 2000);
			socket.setTcpNoDelay(true);
			socket.startHandshake();
			
			DataInputStream in = new DataInputStream(socket.getInputStream());
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String s = "GET " + uri + " HTTP/1.1\r\n";
            s+= "Accept: */*\r\n";
            s+= "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\r\n";
            s+= "Host: " + addr + (port == 443 ? "" : ":"+port) + "\r\n";
            s+= "Connection: Close\r\n";
            s+= "\r\n";
            out.write(s.getBytes());
            out.flush();

			System.out.println(socket.getSession().getCipherSuite());
			
			byte[] buf = new byte[8192];
			int len = in.read(buf);
			if (len == -1)
			{
				System.out.println("eof");
				return;
			}
			System.out.println(new String(buf, 0, len));
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

	public static SSLSocketFactory createSocketFactory(KeyStore kepair, char[] pwd) throws Exception
	{
		TrustAllManager[] trust = { new TrustAllManager() };

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

		SSLSocketFactory factory = ctx.getSocketFactory();
		return factory;
	}
}
