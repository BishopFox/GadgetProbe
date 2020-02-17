package burp.Signatures;

import java.util.Set;

public abstract class Signature {
    protected Set<String> found;
    protected Set<String> notFound;
    protected String[] SIGNATURES;

    public abstract String getName();
    public abstract String getVersion();

    public Signature(Set<String> found, Set<String> notFound) {
        this.found = found;
        this.notFound = notFound;
    }

    public boolean greaterThan() {
        return found.contains(SIGNATURES[0]);
    }

    public boolean lessThan() {
        return notFound.contains(SIGNATURES[1]);
    }

    public boolean equals() {
        return !greaterThan() && !lessThan()
                && notFound.contains(SIGNATURES[0])
                && found.contains(SIGNATURES[1]);
    }

    public boolean missing() {
        return notFound.contains(SIGNATURES[2]);
    }

    public String[] getSignatures() {
        return SIGNATURES;
    }

    public String getResult() {
        StringBuilder sb = new StringBuilder();
        if (missing()) {
            sb.append(getName());
            sb.append(": Not found\n");
            return sb.toString();
        }

        if (greaterThan()) {
            sb.append(getName());
            sb.append(": detected version > ");
            sb.append(getVersion());
            sb.append("\n");
        }
        if (lessThan()) {
            sb.append(getName());
            sb.append(": detected version < ");
            sb.append(getVersion());
            sb.append("\n");
        }
        if (equals()) {
            sb.append(getName());
            sb.append(": detected version == ");
            sb.append(getVersion());
            sb.append("\n");
        }
        if (!lessThan() && !greaterThan() && !equals() && !missing()) {
            sb.append(getName());
            sb.append(": Missing signature queries. Try running the bundled wordlists.\n");
        }
        return sb.toString();
    }
}
