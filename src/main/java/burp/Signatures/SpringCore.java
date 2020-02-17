package burp.Signatures;

import java.util.Set;

public class SpringCore extends Signature {

    public SpringCore(Set<String> found, Set<String> notFound) {
        super(found, notFound);
        SIGNATURES = new String[] {
                // spring-core 4.3.25.RELEASE Class (greater than)
                "org.springframework.asm.CurrentFrame",
                // spring-core 4.1.4.RELEASE Class (equals)
                "org.springframework.asm.TypePath",
                // spring-core class that appears in multiple versions (less than)
                "org.springframework.asm.AnnotationVisitor"
        };
    }

    @Override
    public String getName() {
        return "spring-core";
    }

    @Override
    public String getVersion() {
        return "4.1.4.RELEASE";
    }
}
