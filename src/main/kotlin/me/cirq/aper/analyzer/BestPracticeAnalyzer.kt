package me.cirq.aper.analyzer

import me.cirq.aper.CHECK_APIS
import me.cirq.aper.analyzer.report.StepReport
import me.cirq.aper.analyzer.report.StepReport.PermissionReport
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.JMethod
import me.cirq.aper.mapping.PermissionCombination
import me.cirq.aper.transformer.HandleRdTransformer
import me.cirq.aper.util.*
import soot.Local
import soot.Scene
import soot.SootMethod
import soot.Unit
import soot.jimple.*
import soot.jimple.internal.JEqExpr
import soot.jimple.internal.JIfStmt
import soot.jimple.internal.JNeExpr
import soot.jimple.internal.JimpleLocal
import soot.toolkits.graph.Block
import soot.toolkits.graph.BlockGraph
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet


enum class BestPracticeFollowType(private val desc: String) {
    PermissionNotDeclared("Permission Not Declared"),
    OnlyDeclared("Only Declare Permission"),

    NoCheck("No Check Step"),
    // have check, flow-sensitive types
    CheckedInSequence("Use Check Before API"),
    CheckNotInSequence("No Check Before API"),

    NoRequest("No Request Step"),
    // have request, path-sensitive types
    RequestedInSequence("Use Request If Not Granted"),
    RequestNotInSequence("No Request If Not Granted"),

    HandledInSequence("Correctly inside Handle"),
    HandleNotInSequence("Not Used Correctly in Handle"),

    UseFallbackHandle("Use Fallback onRequestPermissionsResult"),
    // only check for whether permission is refered
    OverrideFallbackNoHandle("No Handle In Customized Fallback"),
    OverrideFallbackWithHandle("Has Handle In Customized Fallback");

    override fun toString(): String {
        return "[${this.javaClass.simpleName}] $desc"
    }
}

typealias BPFollowSituation = Set<BestPracticeFollowType>
// for each permission, whether it follows best practice
private typealias BPFollowSituationMap = MutableMap<APermission,BPFollowSituation>


/**
 * Find whether developer follows the best practice suggested by Android documentation
 *  in https://developer.android.com/training/permissions/requesting.
 *
 * Termly, called the "Synchronous happened-before analysis"
 *
 * The CHECK analysis is flow-sensitive, indicate that check must be taken before api
 * The REQUEST analysis is path-sensitive, so request must be taken if check fails
 */

object BestPracticeAnalyzer {

    fun synchronousAnalyze(reports: Set<StepReport>,
                           dump: Boolean=false): Map<String,BPFollowSituation> {
        val stepReport = HashMap<String,List<String>>()
        val syncReport = HashMap<String,BPFollowSituation>()
        reports.forEach{
            // for every call chain
            val followType: BPFollowSituationMap = HashMap()
            val desc = LinkedList<String>()
            it.permissionReports.forEach innerfor@ { (p, pm) ->
                followType[p] = analyzeFollowType(pm, p, it.chain)
                desc += "$p declared=${pm.isDeclared} with " +
                        "${pm.checkSites.size}-CHECK/" +
                        "${pm.requestSites.size}-REQUEST/" +
                        "${pm.handleCallbacks.size}-HANDLE"
            }
            stepReport[it.storePath.toString()] = desc

            // aggregate results
            val agg = aggregateFollowTypes(it.api, followType)
            syncReport[it.storePath.toString()] = agg
        }
        if(dump) {
            val r = syncReport.map{ (path, types) ->
                val result = types.joinToString(", ", "$path\n#{ ", " }\n")
                val detail = stepReport[path]!!.joinToString("\n", postfix="\n\n----\n")
                result+detail
            }
            FileUtil.writeListTo(r, "syncreport.txt")
        }
        return syncReport
    }


    private fun analyzeFollowType(pm: PermissionReport,
                                  p: APermission,
                                  chain: List<JMethod>): BPFollowSituation {
        val hasCheck = pm.checkSites.isNotEmpty()
        val hasRequest = pm.requestSites.isNotEmpty()
        val overrideHandle = pm.handleCallbacks.isNotEmpty() &&
                            !pm.handleCallbacks[0].isSupportList() // only first handle counts (top caller)
        if(!pm.isDeclared) {
            return setOf(BestPracticeFollowType.PermissionNotDeclared)
        }
        else if(!hasCheck && !hasRequest && !overrideHandle) {
            return setOf(BestPracticeFollowType.OnlyDeclared)
        }
        else{
            val types: MutableSet<BestPracticeFollowType> = HashSet()

            // at this stage, the value of permission must be validate, so
            // here is no need to track dataflow for CHECK/REQUEST parameters
            // only control flow analysis is conducted here

            if(hasCheck) {
                /**
                    +--------+  Double slash for call chain, arrow for other call relation
                    |        |
                    +--------+
                        ||
                        ||        (the `checker`, can also be the chk SDK-api itself)
                    +--------+    +--------+    +-------+
                    |`caller`+---->        +---->  chk  |
                    +--------+    +--------+    +-------+
                        ||
                        ||
                    +--------+(the `apiCaller`, can also be the DangerousAPI itself)
                    |        |
                    +--------+
                        ||
                        ||
                    +--------+
                    |  dapi  |
                    +--------+

                    The task here is to determine whether checker is invoked before apiCaller
                    Assume that check may be wrapped
                */

                pm.checkSites.forEach{ (index, checker, _, invoke) ->
                    val caller = Scene.v().getMethod(chain[index])
                    val apiCaller = Scene.v().getMethod(chain[index+1])
//                    if(invoke checkFor p) {
                        if(synchonouslyCheckedBefore(caller, checker, apiCaller)) {
                            // only keep the **in** type
                            types.add(BestPracticeFollowType.CheckedInSequence)
                            return@forEach
                        }
//                    }
                }
                if(BestPracticeFollowType.CheckedInSequence !in types)
                    types.add(BestPracticeFollowType.CheckNotInSequence)
            }
            else {
                types.add(BestPracticeFollowType.NoCheck)
            }

            if(hasRequest) {
                /**
                    According to the official documentation

                    if(ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS)
                                        != PackageManager.PERMISSION_GRANTED) {
                        // Permission is not granted, should we show an explanation?
                        if(ActivityCompat.shouldShowRequestPermissionRationale(this,
                                                                               Manifest.permission.READ_CONTACTS)) {
                            // Show an explanation to the user *asynchronously*
                            // no need to request since user blocked
                        } else {
                            // No explanation needed; request the permission
                            ActivityCompat.requestPermissions(this,
                                                              new String[]{Manifest.permission.READ_CONTACTS},
                                                              MY_PERMISSIONS_REQUEST_READ_CONTACTS);
                        }
                    } else {
                        // Permission has already been granted
                    }
                 */

                pm.requestSites.forEach{ (index, requester, _, invoke) ->
                    val caller = Scene.v().getMethod(chain[index])
                    if(synchonouslyCheckedThen(caller, requester)) {
                        types.add(BestPracticeFollowType.RequestedInSequence)
                        return@forEach
                    }
                }
                if(BestPracticeFollowType.RequestedInSequence !in types)
                    types.add(BestPracticeFollowType.RequestNotInSequence)
            }
            else {
                types.add(BestPracticeFollowType.NoRequest)
            }

            if(chain.first().isHandleApi()) {
                // The protected-API is invoked inside HANDLE, thus no need
                // to check nor request, simply invoking it is valid.
                // Also note that the HANDLE must be reimplemented hence
                // the value of `overrideHandle` must be true
                check(overrideHandle)

                val entry = Scene.v().getMethod(chain.first())
                val dcaller = Scene.v().getMethod(chain[1])
                if(invokeWithCorrectHandle(entry, dcaller) ||
                        BestPracticeFollowType.CheckedInSequence in types)
                    types.add(BestPracticeFollowType.HandledInSequence)
                else
                    types.add(BestPracticeFollowType.HandleNotInSequence)
            }

            if(overrideHandle) {
                pm.handleCallbacks.forEach{
                    if(usePermissionInHandle(it, p)){
                        types.add(BestPracticeFollowType.OverrideFallbackWithHandle)
                        return@forEach
                    }
                }
                if(BestPracticeFollowType.OverrideFallbackWithHandle !in types)
                    types.add(BestPracticeFollowType.OverrideFallbackNoHandle)
            }
            else {
                types.add(BestPracticeFollowType.UseFallbackHandle)
            }

            return types
        }
    }


    /**
     * Analyze whether the given call-chain starting from [method], which invokes
     * permission-protected API via [caller], is correctly used inside handle method
     *
     * @param method: the entry method, ie, the `onRequestPermissionsRequest`
     * @param caller: the permission-protected API wraper or itself
     *
     * @return whether the [caller] is correctly invoked in [method]
     */
    private fun invokeWithCorrectHandle(method: SootMethod, caller: SootMethod): Boolean {
        val cfg = CFGUtil.getUnitGraph(method)

        fun isCheckForResult(ifs: IfStmt): Boolean {
            val ifcond = ifs.condition.useBoxes
            ifcond.map{it.value}.filterIsInstance<Local>().forEach { local ->
                val cdfact = HandleRdTransformer.handleRdFactAt(method, local, ifs)
                cdfact.filterIsInstance<AssignStmt>().filter {
                    it.rightOp is ArrayRef
                }.forEach { assign ->
                    val base = (assign.rightOp as ArrayRef).base as JimpleLocal
                    val arrfact = HandleRdTransformer.handleRdFactAt(method, base, ifs)
                    if(arrfact.any{it is IdentityStmt})
                        return true     // there are only one param that is int[]
                }
            }
            return false
        }

        fun findAllValidIfStmts(): Iterator<IfStmt> = iterator {
            method.activeBody.units.forEach {
                if(it is IfStmt && it.condition is ConditionExpr &&
                        (it.condition as ConditionExpr).op1.isIntType()) {
                    val ifstmt = it as IfStmt
                    if(isCheckForResult(ifstmt)) {
                        yield(ifstmt)
                    }
                }
            }
        }

        fun invokeAfter(m: SootMethod, unit: Unit): Boolean {
            val stack = LinkedList<Unit>()
            stack.push(unit)
            while(stack.isNotEmpty()) {
                val cur = stack.pop()
                if(cur is Stmt && cur.containsInvokeExpr() && cur.invokeExpr.method==m)
                    return true
                cfg!!.getSuccsOf(cur).forEach {
                    stack.push(it)
                }
            }
            return false
        }

        if(cfg != null) {
            findAllValidIfStmts().forEach {
                val takeBranch = it.target
                val failBranch = cfg.getSuccsOf(it).first{ s->s!=it.target }
                // the correct way is to invoke when user is granted
                val grantedBranch = if(takeIsGranted(it)) takeBranch else failBranch
                if(invokeAfter(caller, grantedBranch))
                    return true
            }
        }
        return false
    }


    private fun aggregateFollowTypes(api: JMethod,
                                     follow: BPFollowSituationMap): BPFollowSituation {
        val result = follow.values.flatten().toMutableSet()
        val pc = PermissionCombination.get(api)
        if(pc == PermissionCombination.AnyOf){
            if(BestPracticeFollowType.PermissionNotDeclared in result && result.size > 1)
                result.remove(BestPracticeFollowType.PermissionNotDeclared)
            // AnyOf permission is ok, so choose the positive one
            if(BestPracticeFollowType.CheckedInSequence in result &&
                    BestPracticeFollowType.CheckNotInSequence in result) {
                result.remove(BestPracticeFollowType.CheckNotInSequence)    // remove!
            }
            if(BestPracticeFollowType.RequestedInSequence in result &&
                    BestPracticeFollowType.RequestNotInSequence in result) {
                result.remove(BestPracticeFollowType.RequestNotInSequence)
            }
            if(BestPracticeFollowType.OverrideFallbackWithHandle in result &&
                    BestPracticeFollowType.OverrideFallbackNoHandle in result) {
                result.remove(BestPracticeFollowType.OverrideFallbackNoHandle)
            }
        }
        if(pc == PermissionCombination.AllOf){
            if(BestPracticeFollowType.PermissionNotDeclared in result && result.size > 1)
                return setOf(BestPracticeFollowType.PermissionNotDeclared)
            // here use the assumption that each permission has either `In` xor `NotIn`
            if(BestPracticeFollowType.CheckedInSequence in result &&
                    BestPracticeFollowType.CheckNotInSequence in result) {
                result.remove(BestPracticeFollowType.CheckedInSequence)    // remove!
            }
            if(BestPracticeFollowType.RequestedInSequence in result &&
                    BestPracticeFollowType.RequestNotInSequence in result) {
                result.remove(BestPracticeFollowType.RequestedInSequence)
            }
            if(BestPracticeFollowType.OverrideFallbackWithHandle in result &&
                    BestPracticeFollowType.OverrideFallbackNoHandle in result) {
                result.remove(BestPracticeFollowType.OverrideFallbackWithHandle)
            }
        }
        return result
    }

    private fun synchonouslyCheckedBefore(caller: SootMethod,
                                          checker: SootMethod,
                                          apiCaller: SootMethod): Boolean {
        var isChecked = false
        CFGUtil.flowIterator(caller).forEach { block ->
            CFGUtil.findAllCallsites(block).forEach { (_, invoke) ->
                if(invoke.method.signature == checker.signature)
                    isChecked = true
                else if(invoke.method.signature==apiCaller.signature && isChecked)
                    return true
            }
        }
        return false
    }

    private fun synchonouslyCheckedThen(caller: SootMethod,
                                        requester: SootMethod): Boolean {
        fun findAllValidChecks(): Iterator<Pair<Block,Unit>> = iterator {
            CFGUtil.findAllCallsites(caller).forEach{ (block, unit, invoke) ->
                if(invoke.method.signature in CHECK_APIS) {
                    yield(Pair(block, unit))
                }
            }
        }
        val cfg = CFGUtil.getGraph(caller)
        if(cfg != null) {
            findAllValidChecks().forEach { (block, unit) ->
                // the jif may comes from the next block which has only one stmt
                val (nb, jif) = getNextJIfStmt(cfg, block, unit) ?: return@forEach
                val takeBranch = cfg.getSuccsOf(nb)
                                   ?.first{ it.head.toString() == jif.target.toString() }
                val failBranch = cfg.getSuccsOf(nb)
                                   ?.first{ it.indexInMethod == nb.indexInMethod + 1 }
                val elseBlock = if (takeIsGranted(jif)) failBranch else takeBranch
                if(elseBlock != null)
                    return requesterReachable(elseBlock, requester)
            }
        }
        return false
    }

    private fun getNextJIfStmt(cfg: BlockGraph,
                               block: Block,
                               unit: Unit): Pair<Block,JIfStmt>? {
        return try {
            Pair(
                block,
                block.getSuccOf(unit) as JIfStmt
            )
        } catch (ex: ClassCastException) {
            val nb = cfg.getSuccsOf(block).firstOrNull {
                it.head is IfStmt
            } ?: return null
            return Pair(nb, nb.head as JIfStmt)
        }
    }

    private fun usePermissionInHandle(handle: SootMethod, permission: APermission): Boolean {
        return handle.hasActiveBody()
    }


    private infix fun InvokeExpr.checkFor(permission: APermission): Boolean {
        val arg = this.args.firstOrNull{
            it.type.toString()=="java.lang.String"
        } ?: return false
        return (arg is StringConstant) && permission.equals(arg.value.toString())
    }


    private const val PERMISSION_DENIED = -1
    private const val PERMISSION_GRANTED = 0

    private fun takeIsGranted(jif: IfStmt): Boolean {
        val cond = jif.condition
        val intBox = cond.useBoxes.first{ it.value is IntConstant }
        val intConst = intBox.value as IntConstant

        return when(cond) {
            is JEqExpr -> intConst.value == PERMISSION_GRANTED
            is JNeExpr -> intConst.value == PERMISSION_DENIED
            else -> false
        }
    }

    private fun requesterReachable(block: Block, requester: SootMethod): Boolean {
        val queue = LinkedList(listOf(block))
        val visited = HashSet<Int>()
        while(queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            visited.add(block.indexInMethod)
            CFGUtil.findAllCallsites(cur).forEach { (_, invoke) ->
                if(invoke.method.signature == requester.signature) {
                    return true
                }
            }
            cur.succs.filter{ it.indexInMethod !in visited }
                     .forEach{ queue.addLast(it) }
        }
        return false
    }

}
