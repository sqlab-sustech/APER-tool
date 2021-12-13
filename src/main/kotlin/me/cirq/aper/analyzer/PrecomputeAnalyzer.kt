package me.cirq.aper.analyzer

import me.cirq.aper.Config
import me.cirq.aper.transformer.*
import me.cirq.aper.util.*
import soot.PackManager
import soot.Scene
import soot.Unit
import soot.options.Options
import java.lang.RuntimeException


object PrecomputeAnalyzer {

    fun runSootPack() {
        if(!Config.get().empiricalCollect && !Config.get().mcgOnly)
            CGUtil.constructCG()

//        Scene.v().init()
        Scene.v().apply_options {
            Config.get().excludedPkgs?.also{
                LogUtil.info(this, "should exclude")
                set_exclude(it)
                set_no_bodies_for_excluded(true)
            }
            set_whole_program(true)
            set_allow_phantom_refs(true)
            set_process_multiple_dex(true)
            set_force_android_jar(Config.get().versionSdkFile.toString())
            set_soot_classpath(Config.get().versionSdkFile.toString())
            set_process_dir(listOf(Config.get().apkFile.toString()))
            set_src_prec(Options.src_prec_apk)
            set_output_format(Options.output_format_none)
            set_validate(false)
            set_verbose(true)
            set_debug(true)
        }
        Scene.v().loadNecessaryClasses()

        PackManager.v().getPack("wjap").apply {
            if(!Config.get().noObfscan)
                addTransform("wjap.obfscan", ObfuscationDetectTransformer())
            if(!Config.get().empiricalCollect && !Config.get().mcgOnly)
                addTransform("wjap.strana", StringAnalysisTransformer())
        }
        PackManager.v().getPack("jap").apply {
            if(Config.get().empiricalCollect)
                addTransform("jap.empb", EmpiricalDataBodyTransformer())
            else if(!Config.get().mcgOnly){
//                (OSEvolutionAnalyzer.targetMin..OSEvolutionAnalyzer.targetMax).forEach { rv ->
//                    addTransform("jap.rv$rv", RVSlicingTransformer(rv))
//                }
                addTransform("jap.hrd", HandleRdTransformer())
            }
        }
        PackManager.v().runPacks()
    }

    fun judgeObfuscation() {
        val lengthCounter: MutableMap<Int, Int> = java.util.HashMap()
        var totalMembers = 0
        ObfuscationDetectTransformer.membersMap.forEach { (_, members) ->
            for (member in members) {
                totalMembers++
                val len = member.length
                val newLen = lengthCounter.getOrDefault(len, 0) + 1
                lengthCounter[len] = newLen
            }
        }
        val shortNames = (lengthCounter[1]?:0) + (lengthCounter[2]?:0)
        val ratio = shortNames.toFloat() / totalMembers
        LogUtil.info(this, "Shortname ratio: $ratio")
        FileUtil.writeStringTo("$ratio", "obf.txt")
        if(ratio > Config.get().obfuscationThreshold)
            throw RuntimeException("Obfuscated APk!")
    }



    private val collector: MutableMap<Unit, Boolean> = HashMap()

    fun add(unit: Unit, exist: Boolean) {
        if(unit !in collector)
            collector[unit] = exist
    }

    fun recordStranaResults() {
        val success = collector.values.sumBy { if(it) 1 else 0 }
        val total = collector.size
        val ratio = success / total.toFloat()
        val message = "Success $success # Total $total # Ratio $ratio"
        FileUtil.writeStringTo(message, "strana.txt")
    }

}
