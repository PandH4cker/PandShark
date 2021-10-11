package protocols.arp;

public enum Operation {
    REQUEST(1, "Request"),
    REPLY(2, "Reply");

    private Integer opcode;
    private String name;
    
    Operation(final Integer opcode, final String name) {
        this.opcode = opcode;
        this.name = name;
    }
}
