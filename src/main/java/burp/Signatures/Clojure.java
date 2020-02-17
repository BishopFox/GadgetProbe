package burp.Signatures;

import java.util.Set;

public class Clojure extends Signature {

    public Clojure(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // clojure 1.9.0 Class (greater than)
                "clojure.lang.EdnReader$NamespaceMapReader",
                // clojure 1.8.0 Class (equals)
                "clojure.core$aclone__inliner__5063",
                // clojure class that appears in multiple versions (less than)
                "clojure.asm.AnnotationVisitor"
        };
    }

    @Override
    public String getName() {
        return "clojure";
    }

    @Override
    public String getVersion() {
        return "1.8.0";
    }
}
