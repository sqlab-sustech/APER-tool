package me.cirq.aper.transformer

import me.cirq.aper.CHECK_APIS
import me.cirq.aper.Config
import me.cirq.aper.REQUEST_APIS
import me.cirq.aper.entity.JClass
import me.cirq.aper.entity.JMethod
import me.cirq.aper.util.CFGUtil
import me.cirq.aper.util.FileUtil
import me.cirq.aper.util.LogUtil
import org.json.JSONObject
import soot.Body
import soot.BodyTransformer
import java.util.concurrent.ConcurrentHashMap
import kotlin.collections.ArrayList
import kotlin.collections.HashMap
import kotlin.collections.HashSet


/* A trivial call-graph implementation */

// from caller to cellees
val callerMap: MutableMap<JMethod, MutableSet<JMethod>> = ConcurrentHashMap()
// from callee to callers
val calleeMap: MutableMap<JMethod, MutableSet<JMethod>> = ConcurrentHashMap()



class EmpiricalDataBodyTransformer: BodyTransformer() {

    /**
     * This transformer is for extracting data for RQ2 (evolving dangerous APIs)
     */

    override fun internalTransform(body: Body, phase: String, options: Map<String,String>) {
        for((_, _, invokExpr) in CFGUtil.findAllCallsites(body.method)) {
            val caller = JMethod.fromSootMethod(body.method)
            val callee = JMethod.fromSootMethod(invokExpr.method)
            val calleeRef = JMethod.fromSootMethod(invokExpr.methodRef.resolve())

            // add forward edge
            if(caller !in callerMap)
                callerMap[caller] = HashSet()
            callerMap[caller]!!.add( callee )
            LogUtil.debug(this, "edge $caller->$callee")

            // add backward edge
            if(callee !in calleeMap)
                calleeMap[callee] = HashSet()
            calleeMap[callee]!!.add( caller )
            LogUtil.debug(this, "edge $callee->$caller")

            // potential group-truth virtual call
            if(calleeRef != callee){
                callerMap[caller]!!.add( calleeRef )
                if(calleeRef !in calleeMap)
                    calleeMap[calleeRef] = HashSet()
                calleeMap[calleeRef]!!.add( caller )
                LogUtil.debug(this, "edge $caller<->$calleeRef")
            }
        }
    }

}

object EmpiricalDataAnalyzer {

    private fun callChainDfs(curPath: MutableList<JMethod>,
                             visited: MutableSet<JMethod>,
                             returnedCallChains: MutableList<List<JMethod>>) {
        val front = curPath.first()
        visited.add(front)
        if(front in calleeMap){
            for(caller in calleeMap[front]!!){
                if(caller !in visited){
                    curPath.add(0, caller)
                    callChainDfs(curPath, visited, returnedCallChains)
                    curPath.removeAt(0)
                }
            }
        }
        else if(curPath.size > 1){
            returnedCallChains.add(ArrayList(curPath))
        }
        visited.remove(front)
    }

    private fun writeEmpiricalCallChains(callChains: List<List<JMethod>>, filename: String){
        val fileLines = ArrayList<String>(callChains.size)
        for(adapiCallChain in callChains){
            val starterPackage = adapiCallChain[0].definingClass.packageId
            var ccString = adapiCallChain.reversed().joinToString(" <-- ")
            ccString += " [$starterPackage]"
            fileLines.add(ccString)
        }
        fileLines.sort()
        FileUtil.writeListTo(fileLines, filename)
    }

    private fun getDapiMethods(path: String): Set<JMethod> {
        val adapiPath = Config.get().mappingDir.resolve(path)
        val adapiLines = FileUtil.readLinesFrom(adapiPath.toString())
        return adapiLines.map{
            JMethod.fromAxplorerSignature(it)
        }.toSet()
    }



    private fun summarizeDapis(){
        val alteredDangerousApis = getDapiMethods("Evolution/evolve_dangerous_apis.txt")
        val adapiCallChains: MutableList<List<JMethod>> = mutableListOf()
        alteredDangerousApis.filter{ it in calleeMap }.forEach{
            callChainDfs(mutableListOf(it), HashSet(), adapiCallChains)
        }
        writeEmpiricalCallChains(adapiCallChains, "adapiCallChains.txt")

        val unchangedDangerousApis = getDapiMethods("Evolution/unchange_dangerous_apis.txt")
        val udapiCallChains: MutableList<List<JMethod>> = mutableListOf()
        unchangedDangerousApis.filter{ it in calleeMap }.forEach{
            callChainDfs(mutableListOf(it), HashSet(), udapiCallChains)
        }
        writeEmpiricalCallChains(udapiCallChains, "udapiCallChains.txt")
    }

    private fun summarizePermissionManagement(){
        val checkCallChains: MutableList<List<JMethod>> = mutableListOf()
        CHECK_APIS.map{ JMethod.fromSootSignature(it) }
                  .filter { it in calleeMap }.forEach{
                callChainDfs(mutableListOf(it), HashSet(), checkCallChains)
            }
        writeEmpiricalCallChains(checkCallChains, "checkCallChains.txt")

        val requestCallChains: MutableList<List<JMethod>> = mutableListOf()
        REQUEST_APIS.map{ JMethod.fromSootSignature(it) }
            .filter { it in calleeMap }.forEach{
                callChainDfs(mutableListOf(it), HashSet(), requestCallChains)
            }
        writeEmpiricalCallChains(requestCallChains, "requestCallChains.txt")
    }

    private fun writeMcg(mcg: Map<JClass,Set<JClass>>) {
        val mcgJson: MutableMap<String,List<String>> = HashMap()
        for((key, value) in mcg)
            mcgJson[key.name] = value.map{ it.name }
        val json = JSONObject(mcgJson).toString()
        FileUtil.writeStringTo(json, "new-mcg.json")
    }



    fun summarize(mcg: Map<JClass,Set<JClass>>?=null){
        if(mcg == null){
            summarizeDapis()
            summarizePermissionManagement()
        }
        else {
            writeMcg(mcg)
        }
    }

}
