package core.headers.layer4;

import java.util.regex.Pattern;

public final class ProtocolDetector {
    private static Pattern ftpPattern = Pattern.compile("^(\\d{3} [ \\w-]+|(ABOR|ACCT|ADAT|ALLO|APPE|AUTH|CCC|CDUP|CLNT|CONF|CWD|" +
            "DELE|ENC|EPRT|EPSV|FEAT|HELP|LANG|LIST|LPRT|LPSV|MDTM|MIC|MKD|MLSD|MLST|MODE|NLST|NOOP|OPTS|PASS|PASV|PBSZ" +
            "|PORT|PROT|PWD|QUIT|REIN|REST|RETR|RMD|RNFR|RNTO|SITE|SIZE|SMNT|STAT|STOR|STOU|STRU|SYST|TYPE|USER|XCUP" +
            "|XMKD|XPWD|XRCP|XRMD|XSEM|XSEN))");

    private static Pattern httpPattern = Pattern.compile("^(((DELETE|GET|HEAD|LINK|OPTIONS|PATCH|POST|PUT|TRACE|UNLINK) " +
                                                         "/.*? HTTP/\\d.\\d)|(HTTP\\/\\d.\\d \\d{3} [a-zA-Z ]*))");

    private static Pattern dnsPattern = Pattern.compile("^(?!((0000)|(.{4}((0000)|(8400)))|(.{24}.*(00200001)$)))." +
                                                        "{8,12}(0001)(.{12})([0-9a-fA-F]{2}[0-9a-fA-F]+)+00([0-9a-fA-F]" +
                                                        "{4}[0-9a-fA-F]{4}.*)");

    private static Pattern dhcpPattern = Pattern.compile("^.{472}63825363.*");

    public static String detectProtocol(final String str) {
        switch (str) {
            case String s && ftpPattern.matcher(s).find() -> {
                return "FTP";
            }
            case String s && httpPattern.matcher(s).find() -> {
                return "HTTP";
            }
            case String s && dnsPattern.matcher(s).find() -> {
                return "DNS";
            }
            case String s && dhcpPattern.matcher(s).find() -> {
                return "DHCP";
            }
            default -> {
                return "UNKNOWN";
            }
        }
    }
}
