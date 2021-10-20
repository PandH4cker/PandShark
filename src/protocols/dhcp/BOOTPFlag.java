package protocols.dhcp;

import protocols.dhcp.exceptions.UnknownFlagCode;

public enum BOOTPFlag {
    UNICAST(0, "Unicast");

    private Integer code;
    private String name;

    BOOTPFlag(final Integer code, final String name) {
        this.code = code;
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public Integer getCode() {
        return code;
    }

    public static BOOTPFlag fromCode(final Integer code) throws UnknownFlagCode {
        for (BOOTPFlag f : BOOTPFlag.values())
            if (f.code.equals(code))
                return f;
        throw new UnknownFlagCode("BOOTPFlag ("+code+") unknown");
    }
}
