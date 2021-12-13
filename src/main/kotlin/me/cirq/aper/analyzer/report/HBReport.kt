package me.cirq.aper.analyzer.report

import me.cirq.aper.ABS_CHECK
import me.cirq.aper.ALTER_CHECK
import me.cirq.aper.Config
import me.cirq.aper.analyzer.*
import me.cirq.aper.analyzer.step.CheckSite
import me.cirq.aper.analyzer.step.RequestSite
import me.cirq.aper.entity.*
import me.cirq.aper.transformer.StringAnalysisTransformer
import me.cirq.aper.util.CGUtil
import me.cirq.aper.util.isBlackList
import me.cirq.aper.util.isHandleApi
import me.cirq.aper.util.isSupportList
import soot.Scene
import soot.SootMethod
import soot.Value
import soot.jimple.StringConstant
import java.nio.file.Path
import java.util.*
import kotlin.collections.ArrayList
import kotlin.collections.HashSet


class HBReport private constructor(
        val api: JMethod,
        val chain: List<JMethod>,
        val storePath: Path
){
    var syncCheck: List<PCallChain>? = null
        private set
    var syncRequest: List<PCallChain>? = null
        private set
    var asyncCheck: List<PCallChain>? = null
        private set
    var asyncRequest: List<PCallChain>? = null
        private set
    lateinit var syncType: Set<BestPracticeFollowType>
        private set
    lateinit var asyncType: Set<HappenBeforeFollowType>
        private set

    companion object {
        fun aggregate(reports: Set<StepReport>,
                      revport: RevStepReport,
                      sync: Map<String,BPFollowSituation>,
                      async: Map<String,HBFollowSituation<ACallChain>>): List<HBReport> {

            return reports.map{ report ->
                val storePath = report.storePath
                val syncresult = sync[storePath.toString()]!!
                val asyncresult = async[storePath.toString()]!!

                val hb = HBReport(report.api, ArrayList(report.chain), storePath)
                hb.syncType = HashSet(syncresult)
                hb.asyncType = HashSet(asyncresult.map{it.first})


                val chk = report.permissionReports.values.map{ it.checkSites }
                var completeCheck = false
                hb.syncCheck = chk.flatten().map{
                    val caller = report.chain[it.first]

                    // if interproc, second points to checker wrapper, otherwise, the check api
                    val checker = it.second
                    if(checker.isSupportList())
                        EmpiricalAnalyzer.addIntraProcedure(storePath, MaintainingAPI.C)
                    else
                        EmpiricalAnalyzer.addInterProcedure(storePath, MaintainingAPI.C)
                    completeCheck = true

                    recoverCChain(caller, it)
                }
                val req = report.permissionReports.values.map{ it.requestSites }
                var completeRequest = false
                hb.syncRequest = req.flatten().map{
                    val caller = report.chain[it.first]

                    val requester = it.second
                    if(requester.isSupportList())
                        EmpiricalAnalyzer.addIntraProcedure(storePath, MaintainingAPI.R)
                    else
                        EmpiricalAnalyzer.addInterProcedure(storePath, MaintainingAPI.R)
                    completeRequest = true

                    recoverRChain(caller, it)
                }
                val syncComplete = completeCheck && completeRequest


                val caller = report.chain.first()
                val map = asyncresult.toMap()
                completeCheck = completeCheck && caller.isHandleApi()   // only this situation, keep the flag
                if(HappenBeforeFollowType.AsyncCheckBeforeUse in map){
                    hb.asyncCheck = map[HappenBeforeFollowType.AsyncCheckBeforeUse]!!
                                        .map{ it as PCallChain }
                    hb.asyncCheck!!.forEach {
                        val checker = it.chain.first()
                        if(checker.definingClass == caller.definingClass)
                            EmpiricalAnalyzer.addInterLifecycle(storePath, MaintainingAPI.C)
                        else
                            EmpiricalAnalyzer.addInterComponent(storePath, MaintainingAPI.C)
                    }
                    completeCheck = true
                }
                completeRequest = false
                if(HappenBeforeFollowType.AsyncRequestBeforeUse in map){
                    hb.asyncRequest = map[HappenBeforeFollowType.AsyncRequestBeforeUse]!!
                                        .map{ it as PCallChain }
                    hb.asyncRequest!!.forEach {
                        val requester = it.chain.first()
                        if(requester.definingClass == caller.definingClass)
                            EmpiricalAnalyzer.addInterLifecycle(storePath, MaintainingAPI.R)
                        else
                            EmpiricalAnalyzer.addInterComponent(storePath, MaintainingAPI.R)
                    }
                    completeRequest = true
                }
                val asyncComplete = completeCheck && completeRequest


                val insideHandle: Boolean = when {
                    BestPracticeFollowType.HandledInSequence in syncresult -> {
                        EmpiricalAnalyzer.addInsideHandle(storePath, true)
                        true
                    }
                    BestPracticeFollowType.HandleNotInSequence in syncresult -> {
                        EmpiricalAnalyzer.addInsideHandle(storePath, false)
                        false
                    }
                    else -> false
                }


                if(!(syncComplete || asyncComplete || insideHandle))
                    EmpiricalAnalyzer.addIncomplete(storePath)

                hb
            }
        }

        private fun recoverCChain(caller: JMethod, cs: CheckSite): PCallChain {
            val chain = traceChain(caller, cs.fourth.method)
            val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(cs.third)
            return PCallChain(chain, saPermission)
        }

        private fun recoverRChain(caller: JMethod, rs: RequestSite): PCallChain {
            val chain = traceChain(caller, rs.fourth.method)
            val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(rs.third)
            return PCallChain(chain, saPermission)
        }

        private fun traceChain(caller: JMethod, tgtMethod: SootMethod): List<JMethod> {
            val stack = LinkedList<SootMethod>()
            val start = Scene.v().getMethod(caller.sootSignature)
            stack.addLast(start)
            check(dfs(stack, HashSet(), Config.get().exLengthThreshold, tgtMethod))
            return stack.map{ JMethod.fromSootSignature(it.signature) }
        }

        // stack expansion, to find start on stack[0], end at tgtMethod
        private fun dfs(stack: LinkedList<SootMethod>,
                        visited: MutableSet<SootMethod>,
                        level: Int, tgtMethod: SootMethod): Boolean {
            if(level == 0)
                return false
            // last is current
            val method = stack.last()
            if(method.signature == tgtMethod.signature)
                return true
            // ugly condition, maybe soot bug
            else if(tgtMethod.signature==ABS_CHECK && method.signature==ALTER_CHECK)
                return true
            visited += method
            CGUtil.getCISCallFrom(method).forEach{ child ->
                if(child.signature == tgtMethod.signature) {
                    stack.addLast(child)
                    return true
                }
                // ugly condition, maybe soot bug
                else if(tgtMethod.signature==ABS_CHECK && child.signature==ALTER_CHECK){
                    stack.addLast(child)
                    return true
                }

                if(child in visited || child.isBlackList())
                    return@forEach
                stack.addLast(child)
                if(dfs(stack, visited, level-1, tgtMethod))
                    return true
                stack.removeLast()
            }
            return false
        }

        private fun Value.toPermission(): APermission {
            require(this is StringConstant)
            return APermission(this.value.toString())
        }
    }

}
