package burp.Signatures;

import java.util.Set;

public class C3p0 extends Signature {

    public C3p0(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // c3p0 0.9.5.3 Class (greater than)
                "",
                // c3p0 0.9.5.2 Class (equals)
                "",
                // c3p0 class that appears in multiple versions (less than)
                "com.mchange.Debug"
        };
    }

    @Override
    public String getName() {
        return "c3p0";
    }

    @Override
    public String getVersion() {
        return "0.9.5.2";
    }
}
