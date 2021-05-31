package com.aliyun.gmsse;

import sun.security.ssl.SSLContextImpl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class RefectUtil {
    public static SSLServerSocketFactory getServerSocketFactory(SSLContext contex) {


        Class c = null;
        try {
            c = Class.forName("sun.security.ssl.SSLServerSocketFactoryImpl");
            Constructor con = c.getDeclaredConstructor(SSLContextImpl.class);
            con.setAccessible(true);
            return (SSLServerSocketFactory) con.newInstance(contex);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return null;

    }
}
