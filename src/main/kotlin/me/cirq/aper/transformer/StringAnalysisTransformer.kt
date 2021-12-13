package me.cirq.aper.transformer

import me.cirq.aper.analyzer.PrecomputeAnalyzer
import me.cirq.aper.entity.APermission
import me.cirq.aper.util.*
import heros.DefaultSeeds
import heros.FlowFunction
import heros.InterproceduralCFG
import heros.flowfunc.Identity
import soot.*
import soot.Unit
import soot.jimple.*
import soot.jimple.infoflow.collect.ConcurrentHashSet
import soot.jimple.internal.JimpleLocal
import soot.jimple.toolkits.ide.DefaultJimpleIFDSTabulationProblem
import soot.jimple.toolkits.ide.JimpleIFDSSolver
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG
import java.lang.RuntimeException
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.collections.HashMap
import kotlin.collections.HashSet


class PermissionValueFact(private val _val: Value, private val _perm: APermission){
    operator fun component1() = _val
    operator fun component2() = _perm

    override fun toString() = "($_val, $_perm)"

    // https://www.baeldung.com/java-equals-hashcode-contracts

    override fun equals(other: Any?) = when(other) {
        is PermissionValueFact -> {
            _val.type == other._val.type &&
            _val.toString() == other._val.toString() &&
            _perm == other._perm
        }
        else -> false
    }

    override fun hashCode() = _val.toString().hashCode() xor _perm.toString().hashCode()
}

/*
    field_xxx for member attribute
    param_xxx for parameter
    local_xxx for variable
 */

class PermissionStringAnalysisProblem(icfg: InterproceduralCFG<Unit, SootMethod>, private val start: Unit):
                                                DefaultJimpleIFDSTabulationProblem<
                                                        PermissionValueFact,
                                                        InterproceduralCFG<Unit, SootMethod>
                                                >(icfg) {

    override fun createZeroValue(): PermissionValueFact {
        val dummyValue = Jimple.v().newLocal("<dummy>", UnknownType.v())
        return PermissionValueFact(dummyValue, APermission.NULL_PERMISSION)
    }

    override fun initialSeeds(): Map<Unit, Set<PermissionValueFact>> = DefaultSeeds.make(setOf(start), zeroValue())

    private fun extractFactString(v: Value): String? {
        if(v.type.toString() == "java.lang.String") {
            when(v) {
                is StringConstant -> {
                    return v.value
                }
                is JimpleLocal -> {
                    // todo: waiting for instances
                }
            }
        }
        return null
    }

    override fun createFlowFunctionsFactory() = object: heros.FlowFunctions<Unit, PermissionValueFact, SootMethod> {

        // https://github.com/Sable/heros/blob/develop/src/heros/FlowFunctions.java

        override fun getNormalFlowFunction(curr: Unit,
                                           succ: Unit): FlowFunction<PermissionValueFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(curr)
            if(m.isSupportList() || m.isBlackList())
                return Identity.v()
            LogUtil.debug(this, "[normal edge] $curr in $m")

            if(curr is DefinitionStmt){
                val leftOp = curr.leftOp    // todo: array leftOp strategyt
                val rightOp = curr.rightOp

                val literal = extractFactString(rightOp) ?: ""
                if(APermission.isPermissionString(literal)){
                    val value = Jimple.v().newLocal("local_$leftOp", leftOp.type)
                    val newFact = PermissionValueFact(value, APermission(literal))
                    return FlowFunction<PermissionValueFact> { source ->
                        if(source == zeroValue()) {
                            Collections.singleton(newFact)
                        }
                        else

                        {
                            setOf(newFact, source)
                        }
                    }
                }
            }
            return FlowFunction { source ->
                Collections.singleton(source)
            }
        }

        override fun getCallFlowFunction(callSite: Unit,
                                         destinationMethod: SootMethod): FlowFunction<PermissionValueFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            if(m.isSupportList() || m.isBlackList())
                return Identity.v()
            LogUtil.debug(this, "[call edge] $callSite in $m")

            val newFacts = mutableSetOf<PermissionValueFact>()
            val invoke = (callSite as Stmt).invokeExpr
            invoke.args.withIndex().forEach{ (i, a) ->
                val argi = extractFactString(a) ?: ""
                if(APermission.isPermissionString(argi)){
                    val value = Jimple.v().newLocal("param_$i", RefType.v())
                    newFacts += PermissionValueFact(value, APermission(argi))
                }
            }

            if(newFacts.isNotEmpty()) {
                return FlowFunction<PermissionValueFact> { source ->
                    if (source == zeroValue()) {
                        newFacts
                    }

                    else {
                        newFacts + source
                    }
                }
            }
            else {
                // what about the fields?
                return FlowFunction { source ->
                    Collections.singleton(source)
                }
            }
        }

        override fun getCallToReturnFlowFunction(callSite: Unit,
                                                 returnSite: Unit): FlowFunction<PermissionValueFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            if(m.isSupportList() || m.isBlackList())
                return Identity.v()
            LogUtil.debug(this, "[call-to-return edge] $callSite to $returnSite in $m")

            return FlowFunction<PermissionValueFact> { source ->
                // not complete
                if(source == zeroValue())
                    Collections.emptySet()
                else

//                if(source.first.toString().startsWith("param_"))
//                    Collections.emptySet()
//                else
                    Collections.singleton(source)
            }
        }

        override fun getReturnFlowFunction(callSite: Unit,
                                           calleeMethod: SootMethod,
                                           exitStmt: Unit,
                                           returnSite: Unit): FlowFunction<PermissionValueFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            if(m.isSupportList() || m.isBlackList())
                return Identity.v()

            // Kill param_ should be completed by the call-to-return, not the return itself

            LogUtil.debug(this, "[return edge] $callSite to $returnSite in $m")

//            return FlowFunction<PermissionValueFact> { source ->
//                if(source == zeroValue())
//                    Collections.emptySet()
//                else
//
//                if(source.first.toString().startsWith("local_"))
//                    Collections.emptySet()
//                else if(source.first.toString().startsWith("param_"))
//                    Collections.emptySet()
//                else
//                    Collections.singleton(source)
//            }

            return FlowFunction { source ->
                Collections.singleton(source)
//                Collections.emptySet()
            }
        }

    }

}


















typealias StringRDFact = Pair<Value, Set<DefinitionStmt>>

class StringReachingDefinitionProblem(icfg: InterproceduralCFG<Unit, SootMethod>,
                                      private val fieldFact: MutableMap<SootField,MutableSet<DefinitionStmt>>,
                                      private val start: Unit,
                                      private val intraP: Boolean=false):
                                                DefaultJimpleIFDSTabulationProblem<
                                                        StringRDFact,
                                                        InterproceduralCFG<Unit, SootMethod>
                                                >(icfg){
    private var universeFacts: MutableSet<DefinitionStmt> = fieldFact[universeFact]!!

    override fun createZeroValue(): StringRDFact {
        val zeroValue = Jimple.v().newLocal("<<zero>>", UnknownType.v())
        return Pair(zeroValue, emptySet())
    }

    override fun initialSeeds(): Map<Unit, Set<StringRDFact>> {
        return DefaultSeeds.make(setOf(start), zeroValue())
    }

    val mFpKillAll = FlowFunction<StringRDFact> { source ->
        val variable = source.first
        if(variable is FieldRef){
            val field = variable.field
            if(field!in fieldFact)
                fieldFact[field] = ConcurrentHashSet()
            fieldFact[field] !!+= source.second
        }
        emptySet()
    }

    override fun createFlowFunctionsFactory() = object: heros.FlowFunctions<Unit, StringRDFact, SootMethod> {

        override fun getNormalFlowFunction(curr: Unit,
                                           succ: Unit): FlowFunction<StringRDFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(curr)
            LogUtil.debug(this, "[normal edge] $curr in $m")

            if(curr is DefinitionStmt) {
                val lval = curr.leftOp
                val rval = curr.rightOp

                if(!lval.isStringType())
                    return Identity.v()
                else {
                    if(lval is ArrayRef) {
                        // ArrayRef must be indexed access, thus the array itself must be initialized
                        val varbase = lval.base
                        return FlowFunction { source ->
                            if (source !== zeroValue())
                                if (source.first.equivTo(varbase) || source.first.equivTo(rval)) {
                                    //    {r2} meets {r2[i1] = r1} -> merge r1 to r2
                                    // or {r3} meets {r2[i1] = r3} -> merge r3 to r2

                                    if(source.second.any { it.toString() == curr.toString() })
                                        return@FlowFunction setOf(source)

                                    val newDefs = source.second + curr
                                    val newFacts = StringRDFact(varbase, newDefs)
                                    universeFacts.addAll(newDefs)
                                    setOf(newFacts)
                                }
                                else
                                    setOf(source)
                            else
                                setOf(source) // at this point, arrayref assign generates NO new fact
                        }
                    }
                    else {
                        val newFact = StringRDFact(lval, setOf(curr))
                        return FlowFunction { source ->
                            if (source !== zeroValue())
                                if (source.first.equivTo(lval))    // overwritten
                                    emptySet()
                                else if (source.first.equivTo(rval) || (
                                                (rval is ArrayRef) && (source.first.equivTo(rval.base))
                                                // {r1} meets {r2 = r1[i1]} -> merge r1 to r2
                                                // note that fetching r1[i1] will not kill r1
                                                )) {

                                    if(source.second.any { it.toString() == curr.toString() })
                                        return@FlowFunction setOf(source)

                                    val newDefs = source.second + curr
                                    val newFacts = StringRDFact(lval, newDefs)
                                    universeFacts.addAll(newDefs)

                                    // only for otf-field analysis, in which no exit edge flow
                                    // will be computed and thus cannot save field defs
                                    if(intraP && (lval is FieldRef)){
                                        val field = lval.field
                                        if(field !in fieldFact)
                                            fieldFact[field] = ConcurrentHashSet()
                                        fieldFact[field] !!+= newDefs
                                    }

                                    setOf(source, newFacts)
                                }
                                else
                                    setOf(source)
                            else {
                                universeFacts.addAll(newFact.second)
                                setOf(newFact)
                            }
                        }
                    }
                }
            }
            else
                return Identity.v()
        }

        override fun getCallFlowFunction(callSite: Unit,
                                         destinationMethod: SootMethod): FlowFunction<StringRDFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            LogUtil.debug(this, "[call edge] $callSite in $m")

            if(destinationMethod.isBlackList())
                return mFpKillAll  // no inter-procedure for library methods

            if(destinationMethod.parameterCount == 0)
                return mFpKillAll

            val invokeExpr = (callSite as Stmt).invokeExpr

            val constantFact = mutableSetOf<StringRDFact>()
            for((idx, arg) in invokeExpr.args.withIndex()) {
                val dest = destinationMethod.getParameterType(idx)
                val param = EquivalentValue(Jimple.v().newParameterRef(dest, idx))
                if(arg is StringConstant && arg.value != "Stub!") {
                    val tmpvar = Jimple.v().newLocal("\$\$p$idx", arg.type)
                    val assign = Jimple.v().newAssignStmt(tmpvar, arg)
                    val newFact = StringRDFact(param, setOf(assign))
                    constantFact.add(newFact)
                }
            }

            return FlowFunction { source ->
                val nonConstantFact = mutableSetOf<StringRDFact>()
                for((idx, arg) in invokeExpr.args.withIndex()) {
                    val dest = destinationMethod.getParameterType(idx)
                    val param = EquivalentValue(Jimple.v().newParameterRef(dest, idx))
                    if(arg == source.first && arg.isStringType()) {
                        // handle passing parameters such as foo($r1)
                        val newFact = StringRDFact(param, source.second)
                        nonConstantFact.add(newFact)
                        break
                    }
                }
                // constant facts do not depend on the other facts, all propagate to callee
                val gen = constantFact + nonConstantFact
                universeFacts.addAll(gen.map{it.second}.flatten())
                gen
            }
        }

        override fun getReturnFlowFunction(callSite: Unit,
                                           calleeMethod: SootMethod,
                                           exitStmt: Unit,
                                           returnSite: Unit): FlowFunction<StringRDFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            LogUtil.debug(this, "[return edge] $callSite to $returnSite in $m")

            return when {
                callSite !is DefinitionStmt -> mFpKillAll
                exitStmt is ReturnVoidStmt -> mFpKillAll
                exitStmt !is ReturnStmt -> mFpKillAll
                else -> {
                    FlowFunction { source ->
                        if(exitStmt.op.equivTo(source.first) && exitStmt.op.isStringType()) {
                            val newFact = StringRDFact(callSite.leftOp, source.second)
                            universeFacts.addAll(source.second)
                            return@FlowFunction setOf(newFact)
                        }
                        emptySet()
                    }
                }
            }
        }

        override fun getCallToReturnFlowFunction(callSite: Unit,
                                                 returnSite: Unit): FlowFunction<StringRDFact> {
            val m: SootMethod = interproceduralCFG().getMethodOf(callSite)
            LogUtil.debug(this, "[call-to-return edge] $callSite to $returnSite in $m")

            return if(callSite !is DefinitionStmt) {
                Identity.v()
            } else {
                FlowFunction { source ->
                    if(callSite.leftOp.equivTo(source.first)) {
                        emptySet()
                    } else {
                        setOf(source)
                    }
                }
            }
        }

    }
}


data class StringFactSolver(
        val problem: StringReachingDefinitionProblem,
        val solver: JimpleIFDSSolver<StringRDFact, InterproceduralCFG<Unit, SootMethod>>
) {
    val id = solver.hashCode()
}

internal val universeFact = Scene.v().makeSootField("<<universe>>", UnknownType.v())

class StringAnalysisTransformer: SceneTransformer() {

    companion object{
        private lateinit var icfg: JimpleBasedInterproceduralCFG
        private lateinit var mainSolver: StringFactSolver
        private val otfSolvers: MutableMap<SootMethod, StringFactSolver> = HashMap()
        private val fieldFact: MutableMap<SootField, MutableSet<DefinitionStmt>> = ConcurrentHashMap()

        init {
            fieldFact[universeFact] = ConcurrentHashSet()
        }

        private fun onTheFlyStrDataflowFactAt(stmt: Unit): Map<Value, Set<DefinitionStmt>> {
            val m = icfg.getMethodOf(stmt)
            if(m !in otfSolvers) {
                LogUtil.info(this, "starting on-the-fly SA solving for $m")
                val entry = m.activeBody.units.first
                val otfProblem = StringReachingDefinitionProblem(icfg, fieldFact, entry)
                val otfSolver = JimpleIFDSSolver(otfProblem)
                otfSolver.solve()
                otfSolvers[m] = StringFactSolver(otfProblem, otfSolver)
            }
            return strDataflowFactAt(stmt, otfSolvers[m]!!)
        }

        private fun onTheFlyFieldFactFor(f: SootField): Set<DefinitionStmt> {
            fun computeOtfFieldFact(subsig: String) {
                try {
                    val m = f.declaringClass.getMethod(subsig)
                    if (m !in otfSolvers) {
                        LogUtil.info(this, "starting on-the-fly field SA solving for $f at ${m.subSignature}")
                        val entry = m.activeBody.units.first
                        val otfProblem = StringReachingDefinitionProblem(icfg, fieldFact, entry, true)
                        val otfSolver = JimpleIFDSSolver(otfProblem)
                        otfSolver.solve()
                        otfSolvers[m] = StringFactSolver(otfProblem, otfSolver)
                    }
                } catch (ex: RuntimeException) {
                    LogUtil.warn(this, "no activebody of $subsig")
                }
            }

            computeOtfFieldFact("void <clinit>()")
            computeOtfFieldFact("void <init>()")
            return fieldFact[f] ?: emptySet()
        }

        private fun strDataflowFactAt(stmt: Unit,
                                      solver: StringFactSolver): Map<Value, Set<DefinitionStmt>> {
            require(stmt is Stmt)

            LogUtil.info(this, "Fetching results at $stmt")

            val refinedResults = HashMap<Value, MutableSet<DefinitionStmt>>()
            // add ifds results
            solver.solver.ifdsResultsAt(stmt).forEach{ (unit, defs) ->
                if(unit !in refinedResults)
                    refinedResults[unit] = HashSet()
                defs.forEach {
                    val rval = it.rightOp
                    if((rval is FieldRef) && (rval.field in fieldFact)){
                        val ff = fieldFact[rval.field]!!
                        refinedResults[unit]!!.addAll(ff)
                    }
                    else if((rval is FieldRef) && (rval.field !in fieldFact)){
                        val fFacts = onTheFlyFieldFactFor(rval.field)
                        refinedResults[unit]!!.addAll(fFacts)
                    }
                    else {
                        refinedResults[unit]!!.add(it)
                    }
                }
            }
            if(refinedResults.isEmpty() && solver.id == mainSolver.id)
                return onTheFlyStrDataflowFactAt(stmt)
            return refinedResults
        }

        private fun strConstantFactAt(stmt: Unit): Map<Value, Set<DefinitionStmt>> {
            require(stmt is Stmt)

            val refinedResults = HashMap<Value, MutableSet<DefinitionStmt>>()
            // add string literal arguments
            if(stmt.containsInvokeExpr()){
                stmt.invokeExpr.args.withIndex().forEach{ (idx, arg) ->
                    if(arg is StringConstant){
                        val argValue = Jimple.v().newLocal("\$\$p$idx", arg.type)
                        val defStmt = Jimple.v().newAssignStmt(argValue, arg)
                        refinedResults[argValue] = mutableSetOf<DefinitionStmt>(defStmt)
                    }
                }
            }
            return refinedResults
        }

        private fun stringConcreteFactAt(stmt: Unit): Map<Value, Set<Value>> {
            val results = strDataflowFactAt(stmt, mainSolver) + strConstantFactAt(stmt)
            val refinedResults = HashMap<Value, MutableSet<Value>>()
            results.forEach { (unit, defs) ->
                if(unit !in refinedResults)
                    refinedResults[unit] = HashSet()
                refinedResults[unit]!!.addAll(defs.map{
                    it.rightOp
                })
            }
            return refinedResults
        }


        private val fallbackPermissionValues: Set<APermission> by lazy {
            fieldFact[universeFact]!!.asSequence()
                    .map { it.rightOp }
                    .filterIsInstance<StringConstant>()
                    .filter { APermission.isPermissionString(it.value) }
                    .map { APermission(it.value) }
                    .toSet()
        }

        fun concretePermissionValuesAt(stmt: Unit): Set<APermission> {
            val results = stringConcreteFactAt(stmt)
            val args = (stmt as Stmt).invokeExpr.args
            val strArg = args.firstOrNull{it.isStringType()}

            val concretePermissions = HashSet<String>()

            if(strArg is StringConstant)
                concretePermissions.add(strArg.value)
            else {
                results[strArg]?.filterIsInstance<StringConstant>()?.forEach {
                    if(APermission.isPermissionString(it.value))
                        concretePermissions.add( it.value )
                }
            }

            return if(concretePermissions.isNotEmpty()) {
                PrecomputeAnalyzer.add(stmt, true)
                concretePermissions.map { APermission(it) }.toSet()
            }
            else {
                PrecomputeAnalyzer.add(stmt, false)
                fallbackPermissionValues
            }
        }

        fun hasConcreteValues(stmt: Unit): Boolean {
            val results = stringConcreteFactAt(stmt)
            val args = (stmt as Stmt).invokeExpr.args
            val strArg = args.firstOrNull{it.isStringType()} ?: return false
            check(strArg.type.toString().startsWith("java.lang.String"))
            if(strArg is StringConstant)
                return true
            else if(results[strArg]?.any{
                        (it is StringConstant) && APermission.isPermissionString(it.value)
                    } == true)
                return true
            return false
        }
    }

    override fun internalTransform(phaseName: String, options: Map<String, String>) {
        kotlin.runCatching {
            val ec = Scene.v().loadClass("dummyMainClass", SootClass.BODIES)
            val em = ec.getMethodByName("dummyMainMethod")
            em.activeBody.units.first
        }.onSuccess { entry ->
            LogUtil.info(this, "starting SA solving stage")
            icfg = CFGUtil.icfg
            val problem = StringReachingDefinitionProblem(icfg, fieldFact, entry)
            val solver = JimpleIFDSSolver(problem)
            solver.solve()
            mainSolver = StringFactSolver(problem, solver)

            LogUtil.info(this, "done solving")
        }.onFailure {
            LogUtil.warn(this, "Unable to construct dummyMain, return")
        }
    }
}
