package me.cirq.aper.analyzer

import me.cirq.aper.SDK_INT_FIELD
import me.cirq.aper.analyzer.report.HBReport
import me.cirq.aper.mapping.Mapping
import me.cirq.aper.tag.RvAvailable
import me.cirq.aper.util.FileUtil
import me.cirq.aper.util.LogUtil
import me.cirq.aper.util.getMethod
import me.cirq.aper.util.last
import soot.*
import soot.Unit
import soot.jimple.*
import soot.toolkits.graph.*
import soot.toolkits.scalar.*
import java.io.InvalidObjectException
import java.nio.file.Path
import java.nio.file.Paths
import java.util.*
import kotlin.Pair
import kotlin.collections.ArrayList
import kotlin.collections.HashMap
import kotlin.collections.LinkedHashMap
import kotlin.math.max


// based on the source code:
// https://github.com/soot-oss/soot/blob/master/src/main/java/soot/toolkits/graph/SimpleDominatorsFinder.java
internal class DesignatedDominatorsAnalysis<N>: ForwardFlowAnalysis<N, FlowSet<N>> {

    private val emptySet: FlowSet<N>
    private val fullSet: BoundedFlowSet<N>
    private val entry: N

    constructor(graph: DirectedGraph<N>, entry: N): super(graph) {
        val nodes = designatedNodeClosure(graph, entry)
        val nodeUniverse = CollectionFlowUniverse(nodes)
        emptySet = ArrayPackedSet(nodeUniverse)
        fullSet = emptySet.clone() as BoundedFlowSet<N>
        fullSet.complement()
        this.entry = entry
        doAnalysis()
    }

    private fun designatedNodeClosure(graph: DirectedGraph<N>, entry: N): ArrayList<N> {
        val nodes =  LinkedList<N>()
        nodes.add(entry)
        var nodeSize: Int
        do {
            nodeSize = nodes.size
            (nodes.clone() as Collection<N>).forEach{ node ->
                graph.getSuccsOf(node).forEach{ succ ->
                    if(succ!in nodes)
                        nodes += succ
                }
            }
        } while(nodes.size != nodeSize)
        return nodes.toCollection(ArrayList())
    }

    override fun newInitialFlow(): FlowSet<N> {
        return fullSet.clone() as FlowSet<N>
    }

    override fun entryInitialFlow(): FlowSet<N> {
        val initSet = emptySet.clone() as FlowSet<N>
        initSet.add(entry)
        return initSet
    }

    override fun flowThrough(`in`: FlowSet<N>, block: N, out: FlowSet<N>) {
        `in`.copy(out)
        out.add(block)
    }

    override fun merge(in1: FlowSet<N>, in2: FlowSet<N>, out: FlowSet<N>) {
        in1.intersection(in2, out)
    }

    override fun mergeInto(block: N, inout: FlowSet<N>, `in`: FlowSet<N>) {
        inout.intersection(`in`)
    }

    override fun copy(source: FlowSet<N>, dest: FlowSet<N>) {
        source.copy(dest)
    }


    fun getDominators(node: N): List<N> = getFlowAfter(node).toList()

}



enum class EvolutionFollowType(private val desc: String) {
    NoRvProtectedAPI("Incompatible RV no Sentinal"),
    RvProtectedAPI("Incompatible RV but Protected by Sentinal"),
    NoCR("No CHECK/REQUEST"), OnlyC("Only CHECK"),
    OnlyR("Only REQUEST"), BothCR("Both CHECK/REQUEST");
}
private typealias EvolutionFollowSituation = Map<Int,EvolutionFollowType>



private class RvReachabilitySolver(val method: SootMethod) {

    private val body: Body = method.activeBody
    private val units: UnitPatchingChain = body.units
    private val cfg: UnitGraph = ExceptionalUnitGraph(body)
    private val analysis: DominatorsFinder<Unit> = SimpleDominatorsFinder<Unit>(cfg)
    private val localDefs: LocalDefs = LocalDefs.Factory.newLocalDefs(body)

    private fun isRvChecker(unit: Unit): Boolean {
        if(!(unit is IfStmt && unit.condition is ConditionExpr)) {
            return false
        }
        val cond = unit.condition as ConditionExpr
        val left = cond.op1
        val right = cond.op2
        var def: List<Unit>? = null

        if(left is Local && left.type is IntType && right is IntConstant)
            def = localDefs.getDefsOfAt(left, unit)
        else if(right is Local && right.type is IntType && left is IntConstant)
            def = localDefs.getDefsOfAt(right, unit)

        return def?.let {
            it.filterIsInstance<AssignStmt>().filter {
                val rop = it.rightOp
                (rop is FieldRef) && (rop.field.signature == SDK_INT_FIELD)
            }.any()
        } ?: false
    }

    private fun rvSatisfy(rv: Int, constrain: ConditionExpr, rightConst: Boolean=true): Boolean {
        return if(rightConst) {
            val const = constrain.op2 as IntConstant
            when (constrain) {
                is LtExpr -> rv < const.value
                is LeExpr -> rv <= const.value
                is GtExpr -> rv > const.value
                is GeExpr -> rv >= const.value
                is NeExpr -> rv != const.value
                is EqExpr -> rv == const.value
                else -> throw InvalidObjectException("unknown cond type: ${constrain.javaClass}")
            }
        }
        else {
            val const = constrain.op1 as IntConstant
            when (constrain) {
                is LtExpr -> const.value < rv
                is LeExpr -> const.value <= rv
                is GtExpr -> const.value > rv
                is GeExpr -> const.value >= rv
                is NeExpr -> const.value != rv
                is EqExpr -> const.value == rv
                else -> throw InvalidObjectException("unknown cond type: ${constrain.javaClass}")
            }
        }
    }

    fun solveAvailableRvs(callsite: Stmt, initRv: Set<Int>): Set<Int> {
        require(callsite in units)

        val dominators = analysis.getDominators(callsite)
        val constrains = dominators.filter{ isRvChecker(it) }

        var rvs = initRv.toMutableSet()
        constrains.forEach{ cond ->
            check(cond is IfStmt && cond.condition is ConditionExpr)
            val constrain = cond.condition as ConditionExpr
            val positive = cond.target
            val negative = units.getSuccOf(cond)
            check(positive != negative)
            rvs = rvs.filter {
                val rightConst = constrain.op2 is Constant
                val followGoto = rvSatisfy(it, constrain, rightConst)
                if(followGoto) {
                    // reachable from positive to callsite
                    val stack = listOf(positive as Unit).toCollection(LinkedList())
                    simpleReachable(stack, callsite)
//                    positive in dominators
                }
                else {
                    // reachable from negative to callsite
                    val stack = listOf(negative as Unit).toCollection(LinkedList())
                    simpleReachable(stack, callsite)
//                    negative in dominators
                }
            }.toMutableSet()
        }
        return rvs
    }


    private fun simpleReachable(stack: LinkedList<Unit>, tgt: Unit): Boolean {
        val front = stack.peek()
        cfg.getSuccsOf(front).forEach {
            if(it == tgt)
                return true
            if((it !in stack)      ){       //&& (it !is ReturnStmt)) {
                stack.push(it)
                if(simpleReachable(stack, tgt))
                    return true
                stack.pop()
            }
        }
        return false
    }

}






typealias RvProtectedCallsite = Pair<Stmt?,List<Int>>








object OSEvolutionAnalyzer {

    private val targetMax: Int
        get() = ManifestAnalyzer.targetSdkVersion
    private val targetMin: Int
        get() = max(23, ManifestAnalyzer.minSdkVersion)


    private fun dumpCompat(storePath: Path, compat: Map<SootMethod,RvProtectedCallsite>){
        val folder = Paths.get("compatibility")

        val sb = StringBuilder()
        sb.appendln(storePath)
        sb.append("\n\n\n")
        compat.forEach{ (method, rpc) ->
            sb.append("In method: ")
            sb.appendln(method.signature)
            val (callsite, rvs) = rpc
            sb.append("   Callsite: ")
            sb.appendln(callsite)
            sb.append("   Protected by: ")
            sb.appendln(rvs.joinToString(","))
            sb.append("\n\n---\n\n")
        }
        val thisPath = folder.resolve(storePath.fileName)
        FileUtil.writeStringTo(sb.toString(), thisPath.toString())
    }

    fun analyzeCompatibility(reports: List<HBReport>, dump: Boolean=false) {
        LogUtil.info(this, "Tagging&Saving RV Sentinal")
        reports.map {
            tagRvSentinal(it)
            val compat = collectCompatibility(it)
            untagRvSentinal(it)
            if(dump)
                dumpCompat(it.storePath, compat)
            it.storePath to analyzeHBreport(it, compat)
        }.also {
            if(dump){
                val sep = "-".repeat(40)
                val content = it.joinToString("\n$sep\n") { (path, hb) ->
                    hb.map { (ver, type) -> "$ver: $type" }.joinToString("\n", "$path\n")
                }
                FileUtil.writeStringTo(content, "compatreport.txt")
            }
        }
    }


    private fun tagCallsiteByRvs(unit: Unit, rvs: Set<Int>) {
        rvs.forEach{
            val tag = RvAvailable.tag(it)
            unit.addTag(tag)
        }
    }

    private fun untagRvSentinal(report: HBReport) {
        report.chain.forEach { m ->
            val method = Scene.v().getMethod(m)
            method.activeBody.units.forEach { unit ->
                val rvs = unit.tags.filterIsInstance<RvAvailable>()
                rvs.forEach{ unit.tags.remove(it) }
            }
        }
    }

    private fun isCallsiteOf(unit: Unit, method: SootMethod): Boolean {
        return if(unit is Stmt && unit.containsInvokeExpr()) {
            unit.invokeExpr.let{ it.method==method || it.methodRef==method}
        }
        else false
    }

    private fun tagRvSentinal(report: HBReport) {
        LogUtil.info(this, "==> TAGGING for chain ${report.storePath}")
        val callpath = report.chain
        var rvRange = (targetMin..targetMax).toSet()
        (0 until callpath.size-1).forEach outter@{ i ->
            val caller = Scene.v().getMethod(callpath[i])
            val callee = Scene.v().getMethod(callpath[i+1])
            val rvSlvr = RvReachabilitySolver(caller)
            caller.activeBody.units.forEach { unit ->
                if(isCallsiteOf(unit, callee)) {
                    val availableRvs = rvSlvr.solveAvailableRvs(unit as Stmt, rvRange)
                    val rvStr = availableRvs.joinToString(",")
                    tagCallsiteByRvs(unit, availableRvs)
                    LogUtil.info(this, "callsite $unit with rvs: [$rvStr]")
                    rvRange = rvRange.intersect(availableRvs)
                    return@outter   // assume the method only call once
                }
            }
        }
    }

    private fun collectCompatibility(report: HBReport): Map<SootMethod,RvProtectedCallsite> {
        // also make the assumption as previous return@outter
        val compatMap = LinkedHashMap<SootMethod,RvProtectedCallsite>()
        report.chain.forEach outter@{ m ->
            val method = Scene.v().getMethod(m)
            method.activeBody.units.forEach { unit ->
                val rv = unit.tags.filterIsInstance<RvAvailable>().map{it.rv}
                if(rv.isNotEmpty()){
                    compatMap[method] = RvProtectedCallsite(unit as Stmt, rv)
                    return@outter
                }
            }
            compatMap[method] = RvProtectedCallsite(null, emptyList())
        }
        return compatMap
    }


    private fun analyzeHBreport(report: HBReport, compat: Map<SootMethod,RvProtectedCallsite>): EvolutionFollowSituation {
        val types = HashMap<Int,EvolutionFollowType>()
        LogUtil.info(this, "Analyzing api usage: {}", report.api)
        (targetMin..targetMax).forEach{ rv ->
            val mapping = Mapping.getArpMethodMapOf(rv)
            val dpermission = mapping[report.api]

            if(dpermission == null) {
                val apiCaller = Scene.v().getMethod(report.chain.last(2))
                val dApi = Scene.v().getMethod(report.api)
                val (callsite, rvs) = compat[apiCaller]!!
                check(callsite!!.invokeExpr.run{ method==dApi||methodRef==dApi })
                if(rv !in rvs) {
                    LogUtil.warn(this, "  In API version {}: no such api, but protected", rv)
                    types[rv] = EvolutionFollowType.RvProtectedAPI
                }
                else {
                    LogUtil.warn(this, "  In API version {}: no such api, protected", rv)
                    types[rv] = EvolutionFollowType.NoRvProtectedAPI
                }
                return@forEach
            }

            val sc = report.syncCheck?.filter{ it.permissions.intersect(dpermission).isNotEmpty() }
                                     ?: emptyList()
            val sr = report.syncRequest?.filter{  it.permissions.intersect(dpermission).isNotEmpty() }
                                       ?: emptyList()
            val ac = report.asyncCheck?.filter{ it.permissions.intersect(dpermission).isNotEmpty() }
                                      ?: emptyList()
            val ar = report.asyncRequest?.filter{ it.permissions.intersect(dpermission).isNotEmpty() }
                                        ?: emptyList()

            val followType = when(Pair( sc.isNotEmpty()||ac.isNotEmpty(),
                                        sr.isNotEmpty()||ar.isNotEmpty() )){
                Pair(false,false) -> EvolutionFollowType.NoCR
                Pair(true,false) -> EvolutionFollowType.OnlyC
                Pair(false,true) -> EvolutionFollowType.OnlyR
                Pair(true,true) -> EvolutionFollowType.BothCR
                else -> throw IllegalStateException("damn kotlin linter")
            }
            types[rv] = followType
            LogUtil.info(this, "  In API version {}: {}", rv, followType)
        }
        return types
    }

}
