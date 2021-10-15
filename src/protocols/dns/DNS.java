package protocols.dns;

import core.headers.layer2.Layer2Protocol;
import core.headers.layer3.Layer3Protocol;
import protocols.PcapPacketData;
import protocols.dns.answer.DNSAnswer;
import protocols.dns.query.DNSQuery;
import utils.bytes.Bytefier;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class DNS extends PcapPacketData {
    private String identifier;
    private DNSFlags dnsFlags;
    private Integer qdCount;
    private Integer anCount;
    private Integer nsCount;
    private Integer arCount;
    private List<DNSQuery> queries;
    private List<DNSAnswer> answers;


    public DNS(final String identifier,
                  final String dnsFlags,
                  final Integer qdCount,
                  final Integer anCount,
                  final Integer nsCount,
                  final Integer arCount,
                  final Integer id,
                  final Integer sequenceNumber,
                  final Layer2Protocol layer2Protocol,
                  final Layer3Protocol layer3Protocol) {
        super(id, sequenceNumber, layer2Protocol, layer3Protocol);
        this.identifier = identifier;

        byte[] dnsFlagsByteArray = Bytefier.hexStringToByteArray(dnsFlags);

        Boolean qr = Bytefier.getBit(dnsFlagsByteArray[0], 7) != 0;
        dnsFlagsByteArray[0] = Bytefier.clearByteAt(dnsFlagsByteArray[0], 7);

        Boolean authoritativeRecurse = Bytefier.getBit(dnsFlagsByteArray[1], 7) != 0;
        dnsFlagsByteArray[1] = Bytefier.clearByteAt(dnsFlagsByteArray[1], 7);

        Integer z = Bytefier.getBit(dnsFlagsByteArray[1], 6) +
                Bytefier.getBit(dnsFlagsByteArray[1], 5) * (1 << 1) +
                Bytefier.getBit(dnsFlagsByteArray[1], 4) * (1 << 2);

        this.dnsFlags = new DNSFlags(qr, (int) Bytefier.getFourthHighest(dnsFlagsByteArray[0]),
                Bytefier.getBit(dnsFlagsByteArray[0], 2) != 0, Bytefier.getBit(dnsFlagsByteArray[0], 1) != 0,
                Bytefier.getBit(dnsFlagsByteArray[0], 0) != 0, authoritativeRecurse,
                z, (int) Bytefier.getFourthLowest(dnsFlagsByteArray[1]));

        this.qdCount = qdCount;
        this.anCount = anCount;
        this.nsCount = nsCount;
        this.arCount = arCount;

        this.queries = new LinkedList<>();
        this.answers = new LinkedList<>();

        /*System.out.println("DNS Queries");
        System.out.println(queries);

        System.out.println("DNS Answers");
        System.out.println(answers);*/
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public DNSFlags getDnsFlags() {
        return dnsFlags;
    }

    public void setDnsFlags(DNSFlags dnsFlags) {
        this.dnsFlags = dnsFlags;
    }

    public Integer getQdCount() {
        return qdCount;
    }

    public void setQdCount(Integer qdCount) {
        this.qdCount = qdCount;
    }

    public Integer getAnCount() {
        return anCount;
    }

    public void setAnCount(Integer anCount) {
        this.anCount = anCount;
    }

    public Integer getNsCount() {
        return nsCount;
    }

    public void setNsCount(Integer nsCount) {
        this.nsCount = nsCount;
    }

    public Integer getArCount() {
        return arCount;
    }

    public void setArCount(Integer arCount) {
        this.arCount = arCount;
    }

    public List<DNSQuery> getQueries() {
        return queries;
    }

    public void setQueries(List<DNSQuery> queries) {
        this.queries = queries;
    }

    public List<DNSAnswer> getAnswers() {
        return answers;
    }

    public void setAnswers(List<DNSAnswer> answers) {
        this.answers = answers;
    }
}