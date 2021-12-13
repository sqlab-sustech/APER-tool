package me.cirq.aper

import me.cirq.aper.analyzer.*
import me.cirq.aper.analyzer.report.HBReport
import me.cirq.aper.analyzer.step.DeclareStep
import me.cirq.aper.mapping.Mapping
import me.cirq.aper.transformer.EmpiricalDataAnalyzer
import me.cirq.aper.util.FileUtil
import me.cirq.aper.util.LogUtil
import kotlin.concurrent.thread
import kotlin.system.exitProcess


private class Main
private val self = Main::class.java

fun main(args: Array<String>) {
    if(args.isNotEmpty() && args[0] == "LocaL") {  // only used for IDE debugging
        Config.get().init(
                "-s", "C:\\Users\\cirq\\Desktop\\arp-tmp\\android-platforms",
                "-M", "C:\\Users\\cirq\\Desktop\\arp-tmp\\DArpMaps",
                "--exclude-libs",
                "--with-exdir",
                "--without-obfscan",
                "--filter-trycatch",

                """C:\Users\cirq\Desktop\arp-tmp\fd-apks\org.nitri.opentopo_26.apk"""
        )
    }
    else {
        Config.get().init(*args)
    }

    if(Config.get().timeout > 0){
        thread(isDaemon=true, name="sentinel") {
            try {
                Thread.sleep(Config.get().timeout * 1000)
                LogUtil.error(self, "--- TIMEOUT ---")
                exitProcess(-1)
            } catch (_: InterruptedException) {}
        }
    }

    val start = System.currentTimeMillis()
    FileUtil.writeStringTo("Target version: ${ManifestAnalyzer.targetSdkVersion}", "target.txt")
    FileUtil.writeStringTo("Package id: ${ManifestAnalyzer.packageName}", "package.txt")

    LogUtil.info(self, "Start soot pre-processing")
    PrecomputeAnalyzer.runSootPack()
    PrecomputeAnalyzer.judgeObfuscation()
    LogUtil.info(self, "Precomputing successfully finished")

    if(Config.get().mcgOnly){
        val mcg = ModuleCGAnalyzer.getModuleCG()
        EmpiricalDataAnalyzer.summarize(mcg)
        LogUtil.info(self, "MCG dumped, exit process")
        LogUtil.info(self, "=== finished ===")
        exitProcess(0)
    }

    if(Config.get().empiricalCollect){
        EmpiricalDataAnalyzer.summarize()
        LogUtil.info(self, "empirical collecting end, exit process")
        LogUtil.info(self, "=== finished ===")
        exitProcess(0)
    }

    LogUtil.info(self, "Start analyzing apk for package {}", ManifestAnalyzer.packageName)
    val mapping = Mapping.get(Config.get().mapping, Config.get().mappingDir, ManifestAnalyzer.targetSdkVersion)
    LogUtil.info(self, "Start collecting api-permission mapping")
    val allPermissionToMethods = mapping.mapPermissionToMethods()
    LogUtil.info(self, "Collected {} mapping with {} items", Config.get().mapping, allPermissionToMethods.size)

    DeclareStep.saveDeclaredPermissions("declaredPermissions.txt")
    LogUtil.info(self, "Dump declared permissions")

    LogUtil.info(self, "Start extracting methods (method analysis)")
    val dangerousApis = MethodAnalyzer.getDangerousApis(allPermissionToMethods)
    LogUtil.info(self, "Collected {} dangerous api-calls", dangerousApis.size)
    FileUtil.writeMethodMapTo(dangerousApis, "dangerousApis.txt")
    var dangerousCallchains = MethodAnalyzer.getDangerousCallchains()
    LogUtil.info(self, "Extracted {} dangerous api-call-chains", dangerousCallchains.size)

    if(Config.get().filterTrycatch){
        dangerousCallchains = MethodAnalyzer.removeWithTrycatch(dangerousCallchains)
        LogUtil.info(self, "After filtering try-catch, {} call-chains remain", dangerousCallchains.size)
    }

//    val ratio = dangerousCallchains.size.toFloat() / dangerousApis.size
////    if(ratio !in 1f..100f) {    // todo: configurable
//    // ratio can only be nan or 0 or positive, cannot replace to '<'
//    if(!(ratio >= 1f)) {
//        LogUtil.warn(self, "Too few or too many call chains, skip")
//        exitProcess(-1)
//    }

    LogUtil.info(self, "Start analyzing (reverse from step)")
    val revreport = StepAnalyzer.reverseAnalyze(dump=Config.get().dumpRevreport)
    LogUtil.info(self, "Reverse step analysis end")

    if(Config.get().completeOnly) {
        val missStep = revreport.run { checkMap.isEmpty() && requestMap.isEmpty() }
        if(missStep) {
            LogUtil.warn(self, "Permission management not complete, skip")
            exitProcess(-1)
        }
    }

    LogUtil.info(self, "Start analyzing steps (step analysis)")
    val report = StepAnalyzer.analyze(dangerousCallchains, dump=Config.get().dumpReport)
    LogUtil.info(self, "Analysis steps end")

    LogUtil.info(self, "For best-practice analysis")
    val sync = BestPracticeAnalyzer.synchronousAnalyze(report, dump=Config.get().dumpReport)
    LogUtil.info(self, "End of best-practice")

    LogUtil.info(self, "For happen-before analysis")
    val async = HappenBeforeAnalyzer.asynchronousAnalyze(report, revreport, dump=Config.get().dumpRevreport)
    LogUtil.info(self, "End of happen-before")

    LogUtil.info(self, "Aggregating reports and results")
    val hbreports = HBReport.aggregate(report, revreport, sync, async)
    EmpiricalAnalyzer.dump()
    LogUtil.info(self, "Analyzing for os-evolution compatibility")
    OSEvolutionAnalyzer.analyzeCompatibility(hbreports, dump=Config.get().dumpReport)
    LogUtil.info(self, "Compatibility report is dumpped and all analysis complete")

    LogUtil.info(self, "Recording string analysis results")
    PrecomputeAnalyzer.recordStranaResults()
    LogUtil.info(self, "Recording success")

    LogUtil.info(self, "=== finished ===")

    val end = System.currentTimeMillis()
    LogUtil.info(self, "Total execution time: {}s", (end-start)/1000f)
}
