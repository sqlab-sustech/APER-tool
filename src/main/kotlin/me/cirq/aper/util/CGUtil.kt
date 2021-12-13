package me.cirq.aper.util

import me.cirq.aper.Config
import soot.*
import soot.jimple.infoflow.InfoflowConfiguration
import soot.jimple.infoflow.InfoflowConfiguration.CallgraphAlgorithm
import soot.jimple.infoflow.android.SetupApplication
import soot.jimple.infoflow.android.config.SootConfigForAndroid
import soot.jimple.toolkits.callgraph.CHATransformer
import soot.jimple.toolkits.callgraph.CallGraph
import soot.jimple.toolkits.callgraph.Sources
import soot.jimple.toolkits.callgraph.Targets
import soot.options.Options


object CGUtil {

    private object CGHolder {
        val inputFormat = when (val f = Config.get().inputFmt.toLowerCase()) {
            "apk" -> Options.src_prec_apk
            "src" -> Options.src_prec_java
            else -> throw IllegalArgumentException("Unsupported input format $f")
        }

        val cgAlgorithm = when (Config.get().cgAlgo.toLowerCase()) {
            "cha" -> CallgraphAlgorithm.CHA
            "geom" -> CallgraphAlgorithm.GEOM
            "rta" -> CallgraphAlgorithm.RTA
            "vta" -> CallgraphAlgorithm.VTA
            else -> CallgraphAlgorithm.SPARK
        }

        lateinit var cg: CallGraph
    }

    fun constructCG() {
        LogUtil.info(this, "Start constructing call graph")
        generateByFlowdroid(CGHolder.inputFormat, CGHolder.cgAlgorithm)
        // generateBySootCHA(inputFormat)
        LogUtil.info(this, "Call graph generated with {} algorithm", CGHolder.cgAlgorithm)
        CGHolder.cg = Scene.v().callGraph
    }

    fun getCallTo(method: SootMethod): Iterator<SootMethod> {
        val parents = Sources(CGHolder.cg.edgesInto(method))
        return object : Iterator<SootMethod> {
            override fun hasNext() = parents.hasNext()
            override fun next() = parents.next().method()
        }
    }

    fun getCallFrom(method: SootMethod): Iterator<SootMethod> {
        val children = Targets(CGHolder.cg.edgesOutOf(method))
        return object : Iterator<SootMethod> {
            override fun hasNext() = children.hasNext()
            override fun next() = children.next().method()
        }
    }

    // CIS for context-insensitive
    fun getCISCallFrom(method: SootMethod): Iterator<SootMethod> {
        val met = HashSet<SootMethod>()
        val children = Targets(CGHolder.cg.edgesOutOf(method))
        children.forEachRemaining{
            if(it.method() !in met)
                met.add(it.method())
        }
        return met.iterator()
    }

    fun getAllCallers(): Iterator<SootMethod> = sequence {
        for (edge in CGHolder.cg) {
            yield(edge.src.method())
        }
    }.iterator()

    fun getAllCallees(): Iterator<SootMethod> = sequence {
        for (edge in CGHolder.cg) {
            yield(edge.tgt.method())
        }
    }.iterator()

    fun getAllEdges(): Iterator<Pair<SootMethod,SootMethod>> = sequence {
        for(edge in CGHolder.cg) {
            val src = edge.src().method()
            val tgt = edge.tgt().method()
            yield(Pair(src, tgt))
        }
    }.iterator()


    private fun generateByFlowdroid(inputFormat: Int, cgAlgorithm: CallgraphAlgorithm) {
        val infoflowApplication = SetupApplication(Config.get().versionSdkFile.toString(),
                Config.get().apkFile.toString())
        infoflowApplication.sootConfig = object : SootConfigForAndroid() {
            override fun setSootOptions(options: Options?, config: InfoflowConfiguration?) {
                super.setSootOptions(options, config)
                config!!.callgraphAlgorithm = cgAlgorithm
                Scene.v().init()
                Scene.v().apply_options {
                    Config.get().excludedPkgs?.also{
                        LogUtil.info(this, "should exclude")
                        set_exclude(it)
                        set_no_bodies_for_excluded(true)
                    }
                    set_force_android_jar(Config.get().versionSdkFile.toString())
                    set_soot_classpath(Config.get().versionSdkFile.toString())
                    set_process_dir(listOf(Config.get().apkFile.toString()))
                    set_src_prec(inputFormat)
                    set_output_format(Options.output_format_dex)
                }
            }
        }
        infoflowApplication.setCallbackFile(Config.get().androidCallbacksFile.toString())
        infoflowApplication.constructCallgraph()
    }


    @Deprecated("never used construct routine")
    private fun generateBySootCHA(inputFormat: Int) {
        G.reset()
        Scene.v().apply_options {
            set_allow_phantom_refs(true)
            set_whole_program(true)
            set_prepend_classpath(true)
            set_process_multiple_dex(true)
            set_validate(true)
            set_force_android_jar(Config.get().versionSdkFile.toString())
            set_soot_classpath(Config.get().versionSdkFile.toString())
            set_process_dir(listOf(Config.get().apkFile.toString()))
            set_src_prec(inputFormat)
            set_output_format(Options.output_format_dex)
        }
        PackManager.v().getPack("wjtp").add(Transform("wjtp.cgcha", object: SceneTransformer(){
            override fun internalTransform(phaseName: String, options: Map<String,String>) {
                CHATransformer.v().transform()
            }
        }))
        Main.v().run(arrayOf(
                "-p", "wjpp", "enabled:true",
                "-p", "wjop", "enabled:false",
                "-p", "wjap", "enabled:false"
        ))
    }

}

fun Iterator<SootMethod>.except(excepted: SootMethod): Iterator<SootMethod> {
    return this.asSequence().filter{ it.signature != excepted.signature }.iterator()
}
