package me.cirq.aper.analyzer

import me.cirq.aper.util.FileUtil
import me.cirq.aper.util.LogUtil
import java.nio.file.Path
import java.nio.file.Paths


enum class MaintainingAPI {
    C, R;
}

object EmpiricalAnalyzer {

    private fun addTo(ccol: MutableSet<Path>,
                      rcol: MutableSet<Path>,
                      report: Path, api: MaintainingAPI) {
        when(api) {
            MaintainingAPI.C -> ccol.add(report)
            MaintainingAPI.R -> rcol.add(report)
        }
    }

    private val intraProcedureC = HashSet<Path>()
    private val intraProcedureR = HashSet<Path>()
    fun addIntraProcedure(report: Path, api: MaintainingAPI) {
        addTo(intraProcedureC, intraProcedureR, report, api)
    }

    private val interProcedureC = HashSet<Path>()
    private val interProcedureR = HashSet<Path>()
    fun addInterProcedure(report: Path, api: MaintainingAPI) {
        addTo(interProcedureC, interProcedureR, report, api)
    }

    private val interLifecycleC = HashSet<Path>()
    private val interLifecycleR = HashSet<Path>()
    fun addInterLifecycle(report: Path, api: MaintainingAPI) {
        addTo(interLifecycleC, interLifecycleR, report, api)
    }

    private val interComponentC = HashSet<Path>()
    private val interComponentR = HashSet<Path>()
    fun addInterComponent(report: Path, api: MaintainingAPI) {
        addTo(interComponentC, interComponentR, report, api)
    }

    private val handleCorrect = HashSet<Path>()
    private val handleIncorrect = HashSet<Path>()
    fun addInsideHandle(report: Path, correct: Boolean) {
        (if(correct) handleCorrect else handleIncorrect).add(report)
    }

    private val incomplete = HashSet<Path>()
    fun addIncomplete(report: Path) {
        incomplete.add(report)
    }

    private fun dumpTwo(f: Set<Path>, s: Set<Path>,
                        first: String="CHECK", second: String="REQUEST"): String {
        return f.joinToString("\n", "$first\n----\n") +
               "\n\n========\n\n" +
               s.joinToString("\n", "$second\n----\n")
    }

    fun dump(){
        LogUtil.debug(this, "here can peek the content in empirical analyzer")
        val empirical = Paths.get("empirical")
        var path: Path

        val intraProcedure = dumpTwo(intraProcedureC, intraProcedureR)
        path = empirical.resolve("intraprocedure.txt")
        FileUtil.writeStringTo(intraProcedure, path.toString())

        val interProcedure = dumpTwo(interProcedureC, interProcedureR)
        path = empirical.resolve("interprocedure.txt")
        FileUtil.writeStringTo(interProcedure, path.toString())

        val interLifecycle = dumpTwo(interLifecycleC, interLifecycleR)
        path = empirical.resolve("interlifecycle.txt")
        FileUtil.writeStringTo(interLifecycle, path.toString())

        val interComponent = dumpTwo(interComponentC, interComponentR)
        path = empirical.resolve("intercomponent.txt")
        FileUtil.writeStringTo(interComponent, path.toString())

        val insideHandle = dumpTwo(handleCorrect, handleIncorrect, "CORRECT", "INCORRECT")
        path = empirical.resolve("insidehandle.txt")
        FileUtil.writeStringTo(insideHandle, path.toString())

        val incompl = incomplete.joinToString("\n")
        path = empirical.resolve("incomplete.txt")
        FileUtil.writeStringTo(incompl, path.toString())

        LogUtil.info(this, "dump empirical done")
    }

}
