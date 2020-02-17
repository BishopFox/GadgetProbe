package burp.Signatures;

import java.util.Set;

public class CommonsCollections4 extends Signature {

    public CommonsCollections4(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // Apache Commons 4.1 Class (greater than)
                "org.apache.commons.collections4.iterators.BoundedIterator",
                // Apache Commons 4.0 Class (equals)
                "org.apache.commons.collections4.iterators.PeekingIterator",
                // Apache Commons class that appears in most versions (less than)
                "org.apache.commons.collections4.iterators.ArrayIterator"
        };
    }

    @Override
    public String getName() {
        return "Apache common-collections4";
    }

    @Override
    public String getVersion() {
        return "4.0";
    }
}
