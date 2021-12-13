package me.cirq.aper;

import me.cirq.aper.analyzer.ManifestAnalyzer;
import org.apache.commons.io.IOUtils;
import picocli.CommandLine;
import picocli.CommandLine.PicocliException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.List;

import static picocli.CommandLine.Option;
import static picocli.CommandLine.Parameters;


public class Config {

    @Parameters(index="0", description="path to apk file")
    public Path apkFile;

    @Option(names={"-h", "--help"}, usageHelp=true, description="display a help message")
    private boolean helpRequested = false;

    @Option(names={"-s", "--sdk"}, required=true, description="path to android sdk jar")
    private Path androidJarDir;

    @Option(names={"-m"}, defaultValue="aper", description="the mapping used")
    public String mapping;     // can only be pscout or axplorer or aper

    @Option(names={"-M", "--mapping-path"}, required=true, description="path to mapping directory (no specifying version)")
    public Path mappingDir;

    @Option(names={"-o", "--output-path"}, defaultValue="analyzerOutput/", description="output path of analyzer")
    private Path outputDir;

    // sadly it sucks
    @Option(names={"-ic3"}, description="path to IC3 model (if no such, disable ICC, use MCG)")
    public Path ic3Model;

    @Option(names={"-i"}, defaultValue="apk", description="input format (default to apk)")
    public String inputFmt;

    @Option(names={"-g"}, defaultValue="CHA", description="call graph algorithm")
    public String cgAlgo;

    @Option(names={"--cc-th"}, defaultValue="10", description="maximum length of call chain")
    public int ccLengthThreshold;

    @Option(names={"--ex-th"}, defaultValue="10", description="maximum length of trace expansion")
    public int exLengthThreshold;

    @Option(names={"--obf-th"}, defaultValue="0.1", description="threshold to judge obfuscation")
    public double obfuscationThreshold;

    @Option(names={"--dump-report"}, description="whether to dump report files (default to false)")
    public boolean dumpReport = true;   // remove default value to disable

    @Option(names={"--dump-revreport"}, description="whether to dump report files (default to false)")
    public boolean dumpRevreport = true;

    @Option(names={"--with-exdir"}, description="don't skip getExternalStorageDirectory in mapping")
    public boolean withExdir = false;

    @Option(names={"--complete-only"}, description="only analyze when permission management is complete")
    public boolean completeOnly = false;

    @Option(names={"-t", "--timeout"}, defaultValue="0", description="timeout in second")
    public long timeout;

    @Option(names={"--exclude-libs"}, description="exclude third party libraries (default to false)")
    private boolean exLibs = false;

    @Option(names={"--without-obfscan"}, description="analyze obfuscated APK")
    public boolean noObfscan = false;

    @Option(names={"--empirical-collect"}, description="run for empirical study data collection")
    public boolean empiricalCollect = false;

    @Option(names={"--mcg-only"}, description="only dump mcg")
    public boolean mcgOnly = false;

    @Option(names={"--filter-trycatch"}, description="filter callchains sourounded by try-catch")
    public boolean filterTrycatch = false;


    public Path apkOutputDir = null;
    public Path versionDangerousFile = null;
    public Path versionSdkFile = null;
    public Path androidCallbacksFile = null;
    public List<String> excludedPkgs = null;





    public void init(String... args) throws IOException {
        try {
            CommandLine cmd = new CommandLine(this);
            cmd.parseArgs(args);
            if(helpRequested){
                cmd.usage(cmd.getOut());
                System.exit(cmd.getCommandSpec().exitCodeOnUsageHelp());
            }

            int apkTargetVersion = ManifestAnalyzer.INSTANCE.getTargetSdkVersion();
            String apkPackageName = ManifestAnalyzer.INSTANCE.getPackageName();

            apkOutputDir = outputDir.resolve(apkPackageName);
            versionDangerousFile = copyToTemp(apkTargetVersion+"Dangerous.txt");
            versionSdkFile = androidJarDir.resolve("android-"+apkTargetVersion).resolve("android.jar");
            androidCallbacksFile = copyToTemp("AndroidCallbacks.txt");
            if(exLibs){
                InputStream exlist = getClass().getClassLoader().getResourceAsStream("exclude_list.txt");
                assert exlist != null;
                excludedPkgs = IOUtils.readLines(exlist, Charset.defaultCharset());
            }
        } catch (PicocliException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }
    }


    private Path copyToTemp(String resname) throws IOException {
        InputStream in = getClass().getClassLoader().getResourceAsStream("arpcompat/"+resname);
        if(in == null) {
            throw new IOException("no such dir: "+resname);
        }
        File temp = File.createTempFile("arpcompat-", ".txt");
        IOUtils.copy(in, new FileOutputStream(temp));
        return temp.toPath();
    }


    private Config(){}

    private static Config singleton = null;

    public static Config get() {
        if(singleton == null)
            singleton = new Config();
        return singleton;
    }

}
