package burp.Signatures;

import java.util.Set;

public class CommonsIO2 extends Signature {

    public CommonsIO2(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // Apache Commons-IO 2.5 Class (greater than)
                "org.apache.commons.io.input.BoundedReader",
                // Apache Commons-IO 2.4 Class (greater than)
                "org.apache.commons.io.input.BOMInputStream$1",
                // Apache Commons class that appears in most versions (less than)
                "org.apache.commons.io.Charsets"
        };
    }

    @Override
    public String getName() {
        return "Apache commons-io";
    }

    @Override
    public String getVersion() {
        return "2.4";
    }
}
