package burp.Signatures;

import java.util.Set;

public class Javassist extends Signature {

    public Javassist(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // javassist 3.26.0-GA Class (greater than)
                "javassist.ByteArrayClassPath$1",
                // javassist 3.20.0-GA Class (equals)
                "javassist.bytecode.annotation.TypeAnnotationsWriter",
                // javassist class that appears in multiple versions (less than)
                "javassist.ByteArrayClassPath"
        };
    }

    @Override
    public String getName() {
        return "javassist";
    }

    @Override
    public String getVersion() {
        return "3.20.0-GA";
    }
}
