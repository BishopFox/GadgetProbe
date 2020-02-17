package burp.Signatures;

import java.util.Set;

public class Groovy239 extends Signature {

    public Groovy239 (Set<String> found, Set<String> notFound) {

        super(found, notFound);
        SIGNATURES = new String[] {
                // groovy-all 2.3.10 Class (greater than)
                "groovy.grape.GrapeIvy$_enumerateGrapes_closure11_closure22",
                // groovy-all 2.3.9 Class (equals)
                "org.codehaus.groovy.classgen.asm.indy.IndyBinHelper",
                // groovy-all class that appears in multiple versions (less than)
                "groovy.beans.BindableASTTransformation"
        };

    }

    @Override
    public String getName() {
        return "groovy-all";
    }

    @Override
    public String getVersion() {
        return "2.3.9";
    }
}
