package core.headers.layer3.ip.v4;

import core.headers.layer3.ip.v4.exceptions.UnknownVersion;

public enum IPVersion {
    IPV4(4, "IPv4"),
    ST_DATAGRAM_MODE(5, "ST Datagram Mode"),
    IPV6(6, "IPv6");

    Integer version;
    String name;

    IPVersion(final Integer version, final String name) {
        this.version = version;
        this.name = name;
    }

    public Integer getVersion() {
        return version;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static IPVersion fromVersion(final Integer version) throws UnknownVersion {
        for(IPVersion e : IPVersion.values())
            if (e.version.equals(version))
                return e;
        throw new UnknownVersion("IPVersion ("+version+") unknown");
    }
}
