package protocols.arp;

import protocols.arp.exceptions.UnknownOperation;

public enum Operation {
    REQUEST(1, "Request"),
    REPLY(2, "Reply");

    private Integer opcode;
    private String name;
    
    Operation(final Integer opcode, final String name) {
        this.opcode = opcode;
        this.name = name;
    }

    public Integer getOpcode() {
        return opcode;
    }

    @Override
    public String toString() {
        return name;
    }

    public static Operation fromOpcode(final Integer opcode) throws UnknownOperation {
        for(Operation op : Operation.values())
            if (op.opcode.equals(opcode))
                return op;
        throw new UnknownOperation("UnknownOperation ("+opcode+") unknown");
    }
}
