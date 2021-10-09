package core.headers.layer3.ip.v4;

public class IPFlags {
    private Boolean reserved;
    private Boolean dontFragment;
    private Boolean moreFragment;

    public IPFlags(final Boolean reserved,
                   final Boolean dontFragment,
                   final Boolean moreFragment) {
        this.reserved = reserved;
        this.dontFragment = dontFragment;
        this.moreFragment = moreFragment;
    }

    public Boolean getDontFragment() {
        return dontFragment;
    }

    public Boolean getMoreFragment() {
        return moreFragment;
    }
}
