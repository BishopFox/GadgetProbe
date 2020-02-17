package burp.Signatures;

import java.util.Set;

public class CommonsCollections3 extends Signature {

    public CommonsCollections3(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // Apache Commons 3.2 Class (greater than)
                "org.apache.commons.collections.iterators.ReverseListIterator",
                // Apache Commons 3.1 Class (equals)
                "org.apache.commons.collections.functors.TransformedPredicate",
                // Apache Commons class that appears in most versions (less than)
                "org.apache.commons.collections.ArrayStack"
        };
    }

    @Override
    public String getName() {
        return "Apache common-collections";
    }

    @Override
    public String getVersion() {
        return "3.1";
    }
}
