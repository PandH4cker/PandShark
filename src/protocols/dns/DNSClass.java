package protocols.dns;

import protocols.dns.exceptions.UnknownQueryClass;

public enum DNSClass {
    INTERNET("IN", 1, "Internet"),
    CSNET("CS", 2, "Class Csnet"),
    CHAOS("CH", 3, "Chaos"),
    HESIOD("HS", 4, "Hesiod");

    private String entry;
    private Integer value;
    private String name;

    DNSClass(final String entry, final Integer value, final String name) {
        this.entry = entry;
        this.value = value;
        this.name = name;
    }

    public static DNSClass fromValue(final Integer value) throws UnknownQueryClass {
        for(DNSClass qc : DNSClass.values())
            if (qc.value.equals(value))
                return qc;
        throw new UnknownQueryClass("UnknownQueryClass ("+value+") unknown");
    }


    @Override
    public String toString() {
        return name;
    }

    public Integer getValue() {
        return value;
    }

    public String getEntry() {
        return entry;
    }
}
