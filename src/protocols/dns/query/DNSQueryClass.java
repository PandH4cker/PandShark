package protocols.dns.query;

import protocols.dns.exceptions.UnknownQueryClass;

public enum DNSQueryClass {
    INTERNET("IN", 1, "Internet"),
    CSNET("CS", 2, "Class Csnet"),
    CHAOS("CH", 3, "Chaos"),
    HESIOD("HS", 4, "Hesiod");

    private String entry;
    private Integer value;
    private String name;

    DNSQueryClass(final String entry, final Integer value, final String name) {
        this.entry = entry;
        this.value = value;
        this.name = name;
    }

    public static DNSQueryClass fromEntryValue(final String entry, final Integer value) throws UnknownQueryClass {
        for(DNSQueryClass qc : DNSQueryClass.values())
            if (qc.entry.equals(entry) && qc.value.equals(value))
                return qc;
        throw new UnknownQueryClass("UnknownQueryClass ("+entry+","+value+") unknown");
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
