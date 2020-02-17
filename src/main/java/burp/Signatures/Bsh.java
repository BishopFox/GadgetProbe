package burp.Signatures;

import java.util.Set;

public class Bsh extends Signature {

    public Bsh(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // bsh 2.0b5 Class (greater than)
                "bsh.CollectionManager$BasicBshIterator$1",
                // bsh 2.0b4 Class (equals)
                "bsh.BSHBlock$NodeFilter",
                // bsh class that appears in multiple versions (less than)
                "bsh.BlockNameSpace"
        };
    }

    @Override
    public String getName() {
        return "bsh";
    }

    @Override
    public String getVersion() {
        return "2.0b4";
    }
}
