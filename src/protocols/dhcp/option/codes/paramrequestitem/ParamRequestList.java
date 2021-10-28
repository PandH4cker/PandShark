package protocols.dhcp.option.codes.paramrequestitem;

import protocols.dhcp.option.DHCPOption;
import protocols.dhcp.option.DHCPOptionCode;

import java.util.List;
import java.util.stream.Collectors;

public class ParamRequestList extends DHCPOption {
    private final List<DHCPOptionCode> paramRequestItemList;

    public ParamRequestList(final List<DHCPOptionCode> paramRequestItemList) {
        super(DHCPOptionCode.PARAM_REQUEST_LIST);
        this.paramRequestItemList = paramRequestItemList;
    }

    @Override
    public String toString() {
        return paramRequestItemList.stream()
                                   .map(opt -> "Paramater Request List Item: " + opt)
                                   .collect(Collectors.joining("\n"));
    }

    public List<DHCPOptionCode> getParamRequestItemList() {
        return paramRequestItemList;
    }
}
