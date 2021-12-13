package me.cirq.aper.analyzer

import me.cirq.aper.Config
import me.cirq.aper.entity.*
import me.cirq.aper.util.LogUtil
import me.cirq.aper.util.SignatureUtil
import me.cirq.aper.util.isBlackList
import me.cirq.aper.util.isModuleInteractionMethod
import soot.Kind
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.jimple.AbstractStmtSwitch
import soot.jimple.InvokeStmt
import soot.util.dot.DotGraph
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet
import kotlin.collections.LinkedHashSet


/**
 * Self-defined Soot phase
 */
object ModuleCGAnalyzer {

    private val methodStack: ArrayDeque<CallerMethod> = ArrayDeque()
    private val manifest: Manifest = ManifestParser(ManifestAnalyzer.manifestText).parse()
    val cmpNames: HashSet<String> = manifest.getNames()

    /**
     * Analyze callsite in individual function
     * @param sootMethod Individual method body
     */
    private fun funcAnalysis(sootMethod: SootMethod, rootClassName: String): LinkedHashSet<Edge> {
        LogUtil.debug(this, "Start analyze method ${sootMethod.name}")
        val edges: LinkedHashSet<Edge> = LinkedHashSet()
        if (!sootMethod.isConcrete) return edges
        val body = sootMethod.retrieveActiveBody()
        /* Travel units in the method body to identify each callsite */
        body.units.forEach {
            it.apply(
                    object : AbstractStmtSwitch() {
                        override fun caseInvokeStmt(stmt: InvokeStmt) {
                            /* Identify context-registered broadcaster receiver */
                            val checkResult = SignatureUtil.parseIntentArg(stmt)
                            if(checkResult == null) {
                                return
                            }
                            if (checkResult.isBCReceiver) {
                                val intentFilter = IntentFilter(checkResult.identifier, methodStack).also { itf ->
                                    itf.backwardSlice(sootMethod, it)
                                }
                                if (intentFilter.findDef) {
                                    LogUtil.debug(this, "Find broadcast receiver at ${sootMethod.declaringClass}")
                                    this@ModuleCGAnalyzer.createReceiver(rootClassName, intentFilter)
                                }
                            }

                            /* Identify Intents */
                            if (!checkResult.isBCReceiver) {
                                LogUtil.debug(this, "Find ${checkResult.apiName} in ${sootMethod.name}")
                                val intent = Intent(checkResult.identifier, methodStack).also { itt ->
                                    itt.backwardSlice(sootMethod, it)
                                }
                                if (intent.findDef) {
                                    LogUtil.debug(this, "Intent resolve successfully!")
                                    edges.add(Edge(rootClassName, checkResult.apiName, intent, null))
                                } else
                                    LogUtil.debug(this, "Intent resolve failed!")
                            }
                        }
                    }
            )
        }
        return edges
    }

    private fun addReceiver(receiver: Receiver) = this.manifest.addReceiver(receiver)

    private fun addCmp(cmpName: String) = this.cmpNames.add(cmpName)

    private fun createReceiver(className: String, intentFilter: IntentFilter) {
        this@ModuleCGAnalyzer.addReceiver((Receiver(className, listOf(intentFilter))))
        this@ModuleCGAnalyzer.addCmp(className)
    }

    /**
     * Recursively find the methods called by the call-back methods
     * @param sootMethod SootMethod body that needs to be analyzed
     * @param rootClassName Class name for the entry point to this method
     * @param depth Current depth (max value is 3)
     * @return Edges found in this method
     */
    private fun funcAnalyzeRecursive(sootMethod: SootMethod, rootClassName: String, depth: Int = 2): LinkedHashSet<Edge> {
        val edges: LinkedHashSet<Edge> = funcAnalysis(sootMethod, rootClassName)
        if (depth > 0) {
            val cg = Scene.v().callGraph
            val it = cg.edgesOutOf(sootMethod)
            while (it.hasNext()) {
                val next = it.next()
                if (next.isClinit || next.kind() == Kind.FINALIZE || !next.srcStmt().containsInvokeExpr()) {
                    continue
                }
                methodStack.push(CallerMethod(next.srcUnit(), sootMethod))
                edges.addAll(funcAnalyzeRecursive(next.tgt as SootMethod, rootClassName, depth - 1))
                methodStack.poll()
            }
        }
        return edges
    }

    fun getModuleCG(): Map<JClass,Set<JClass>> {
        LogUtil.info(this, "Start extracting module call graph. Total ${cmpNames.size} application class")
        val wholeEdge: HashSet<Edge> = HashSet()
        for (sootClass: SootClass in Scene.v().classes) {
            if(!sootClass.name.isComponent())
                continue
            val sootMethods = sootClass.methods.toTypedArray()
            for (sootMethod: SootMethod in sootMethods) {
                /* Find all call-back functions as the entry point of each component */
//                if (sootMethod.name.isEntry()) {
                    wholeEdge.addAll(funcAnalyzeRecursive(sootMethod, sootClass.name, 3))
//                }
            }
        }
        LogUtil.info(this, "Total: ${wholeEdge.size} edges in module call graph")

        val graphConstructor = GraphConstructor(this.manifest, wholeEdge)
        val dotPath = Config.get().apkOutputDir.resolve("mcg.dot")
        graphConstructor.drawGarph(dotPath.toString())
        LogUtil.info(this, "Draw mcg to dot")

        return adapt(graphConstructor.edges)
    }

    private fun String.isEntry(): Boolean = this.startsWith("on") || this == "<init>"

    private fun String.isComponent(): Boolean = (this.substringBefore("$") in this@ModuleCGAnalyzer.cmpNames)
}



class GraphConstructor(private val manifest: Manifest, edges: Set<Edge>) {
    val edges: Set<Pair<String, String>>
    val nodes: Set<String>

    init {
        this.edges = getEdges(edges)
        this.nodes = getNodes(this.edges)
    }

    private fun getOutEdgeExplict(edge: Edge): String {
        val outEdge = edge.intent.targetComponent
                ?.removePrefix("L")
                ?.removeSuffix(";")
                ?.replace("/", ".")
        return if (outEdge == null) "" else outEdge
    }

    private fun matchActivity(edge: Edge): List<String> =
            this.manifest.activity
                    .filter { it.match(edge.intent) }
                    .map { it.name }

    private fun matchService(edge: Edge): List<String> =
            this.manifest.service
                    .filter { it.match(edge.intent) }
                    .map { it.name }

    private fun matchReceiver(edge: Edge): List<String> =
            this.manifest.receiver
                    .filter { it.match(edge.intent) }
                    .map { it.name }

    private fun getOutEdgeImplicit(edge: Edge): List<String> {
        if ("activity" in edge.apiName.toLowerCase()) {
            return matchActivity(edge)
        }
        if ("service" in edge.apiName.toLowerCase()) {
            return matchService(edge)
        }
        if ("broadcast" in edge.apiName.toLowerCase()) {
            return matchReceiver(edge)
        }
        return listOf()
    }

    private fun getOutEdge(edge: Edge): List<String> {
        return if (edge.intent.targetComponent != null) {
            listOf(getOutEdgeExplict(edge))
        } else {
            getOutEdgeImplicit(edge)
        }
    }

    private fun getEdges(edges: Set<Edge>): Set<Pair<String, String>> {
        return edges.flatMap {
            getOutEdge(it).map { t ->
                Pair(it.inCmp, t)
            }
        }.toSet()
    }

    private fun getNodes(edges: Set<Pair<String, String>>): Set<String> {
        return edges.map { it.toList() }.flatten().toSet()
    }

    fun drawGarph(graphName: String) {
        val dotGraph = DotGraph(graphName)
        with(dotGraph) {
            (this@GraphConstructor.nodes).forEach { drawNode(it) }
            (this@GraphConstructor.edges).forEach { drawEdge(it.first, it.second) }
        }
        dotGraph.plot(graphName)
    }
}



private fun adapt(graph: Set<Pair<String,String>>): Map<JClass,Set<JClass>>{

    fun convert(cmp: String): JClass {
        val str = cmp.replace("""\$\d+""".toRegex(), "")
        return JClass(str)
    }

    val newGraph = HashMap<JClass,MutableSet<JClass>>()
    for((src, tgt) in graph){
        val innode = JClass(src)
        val outnode = JClass(tgt)
        if(innode !in newGraph)
            newGraph[innode] = HashSet()
        newGraph[innode]!!.add(outnode)
    }
    return newGraph
}
