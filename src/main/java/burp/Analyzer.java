package burp;

import burp.Signatures.*;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;

public class Analyzer {
    private static Class[] checks = new Class[] {
            Bsh.class,
            C3p0.class,
            Clojure.class,
            CommonsCollections4.class,
            CommonsCollections3.class,
            CommonsIO2.class,
            Groovy239.class,
            HibernateCore.class,
            Javassist.class,
            SpringCore.class
    };

    public static String Analyze(Set<String> found, Set<String> notFound) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < checks.length; i++) {
            Signature s = null;
            try {
                s = (Signature) (checks[i].getConstructor(new Class[]{Set.class, Set.class}).newInstance(found, notFound));
            } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
            }
            sb.append(s.getResult());
        }

        return sb.toString();
    }

    public static String getWordlist() {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < checks.length; i++) {
            Signature s = null;
            try {
                s = (Signature) (checks[i].getConstructor(new Class[]{Set.class, Set.class}).newInstance(null, null));
            } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
            }
            String[] classnames = s.getSignatures();
            for (int j = 0; j < classnames.length; j++) {
                if (classnames[j].length() > 0) {
                    sb.append(classnames[j]);
                    sb.append("\n");
                }
            }
        }
        sb.delete(sb.length() - 1, sb.length());

        return sb.toString();
    }

}
