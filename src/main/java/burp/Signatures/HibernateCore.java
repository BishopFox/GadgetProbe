package burp.Signatures;

import java.util.Set;

public class HibernateCore extends Signature {

    public HibernateCore(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // hibernate-core 5.1.17.Final Class (greater than)
                "org.hibernate.annotations.LazyGroup",
                // hibernate-core 5.0.7.Final Class (equals)
                "org.hibernate.boot.archive.spi.JarFileEntryUrlAdjuster",
                // hibernate-core class that appears in multiple versions (less than)
                "org.hibernate.action.internal.AbstractEntityInsertAction"
        };
    }

    @Override
    public String getName() {
        return "hibernate-core";
    }

    @Override
    public String getVersion() {
        return "5.0.7.Final";
    }
}
