package me.cirq.aper.analyzer

import me.cirq.aper.Config
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.DCallChain
import me.cirq.aper.entity.JMethod
import me.cirq.aper.util.*
import soot.Scene
import soot.SootClass
import soot.SootMethod
import soot.toolkits.graph.ExceptionalUnitGraph
import java.util.*
import kotlin.collections.HashMap
import kotlin.collections.HashSet


object MethodAnalyzer {

    private val apiToDangerousPermissions: MutableMap<JMethod,MutableSet<APermission>> = HashMap()
    private val dangerousCallChains: MutableSet<DCallChain> = HashSet()

    private val applicationMethods: Map<JMethod,SootMethod> by lazy {
        val appMethods = HashMap<JMethod,SootMethod>()
        for(sootClass in Scene.v().applicationClasses) {
            for(sootMethod in sootClass.methods) {
                val method = JMethod.fromSootSignature(sootMethod.signature)
                appMethods[method] = sootMethod
            }
        }
        appMethods
    }


    fun getDangerousApis(allPermissionToApis: Map<APermission,Set<JMethod>>): Map<JMethod,Set<APermission>> {
        if(apiToDangerousPermissions.isNotEmpty())
            return apiToDangerousPermissions

        val apiToPermissions: Map<JMethod,Set<APermission>> = getApiToPermissions(allPermissionToApis)
        apiToPermissions.forEach { (method, permissions) ->
            if(method !in apiToDangerousPermissions) {
                apiToDangerousPermissions[method] = HashSet()
            }
            apiToDangerousPermissions[method]!!.addAll(permissions)
            LogUtil.info(this, "Method #{}# for dangerous permission {}", method, permissions)
        }
        return apiToDangerousPermissions
    }

    private fun getApiToPermissions(allPermissionToApis: Map<APermission,Set<JMethod>>): Map<JMethod,Set<APermission>> {
        val apiToPermissions: MutableMap<JMethod, MutableSet<APermission>> = HashMap()
        CGUtil.getAllEdges().forEach { (caller, callee) ->
            if(caller.isSupportList())
                return@forEach
            val method = JMethod.fromSootSignature(callee.signature)
            allPermissionToApis.forEach { (permission, apis) ->
                if(method in apis) {
                    if(!apiToPermissions.containsKey(method)) {
                        apiToPermissions[method] = HashSet()
                    }
                    apiToPermissions[method]!!.add(permission)
                }
            }
        }
        return apiToPermissions
    }



    fun getDangerousCallchains(): Set<DCallChain> {
        if(dangerousCallChains.isNotEmpty())
            return dangerousCallChains

        if(apiToDangerousPermissions.isEmpty())
            throw RuntimeException("No dangerous methods found")
        for(api in apiToDangerousPermissions.keys) {
            val callChain = LinkedList<JMethod>()
            callChain.addFirst(api)
            travelCallGraph(callChain, HashSet()) { chain ->
                val permissions = apiToDangerousPermissions[chain.last]
                dangerousCallChains += DCallChain(chain, permissions!!)
            }
        }
        return dangerousCallChains
    }

    fun collectCallchainsTo(method: JMethod, collector: (LinkedList<JMethod>)->Unit) {
        val currentChain = LinkedList<JMethod>()
        currentChain.addFirst(method)
        travelCallGraph(currentChain, HashSet(), collector)
    }


    private fun travelCallGraph(chain: LinkedList<JMethod>,
                                visited: MutableSet<JMethod>,
                                visitor: (LinkedList<JMethod>)->Unit) {
        if(terminateAtSelf(chain)) {
            visitor(chain)
            return
        }

        val method = chain.first
        visited.add(method)

        kotlin.runCatching {
            val clazz = Scene.v().loadClass(method.definingClass.name, SootClass.BODIES)
            clazz.getMethod(method. sootSubSignature)
        }.onSuccess {
            CGUtil.getCallTo(it).forEach { parent ->
                val nextMethod = JMethod.fromSootSignature(parent.signature)
                if(parentReachSdk(nextMethod) && chain.size==1){
                    // do nothing, nor expand or visit
                }
                else if(parentReachSdk(nextMethod) || parentReachDummy(nextMethod)) {
                    visitor(chain)
                }
                else if(nextMethod !in visited) {
                    chain.addFirst(nextMethod)
                    travelCallGraph(chain, visited, visitor)
                    chain.removeFirst()
                }
            }
        }.onFailure {
            LogUtil.warn(this, "no such method: ${method.sootSignature}")
        }
    }

    private fun terminateAtSelf(chain: List<JMethod>) = chain.size>1 && (
            selfReachThreshold(chain) ||
            selfReachUncaughtException(chain) || selfReachLambdaRunnable(chain) ||
            selfReachRunnable(chain) || selfReachCallable(chain))

//    private fun terminateAtParent(chain: List<JMethod>, parent: JMethod) = chain.size>1 && (
//            parentReachDummy(parent) || parentReachSdk(parent))

    private fun selfReachThreshold(chain: List<JMethod>) = chain.size >= Config.get().ccLengthThreshold

    private fun selfReachUncaughtException(chain: List<JMethod>): Boolean {
        if(chain[0].methodName != "uncaughtException")
            return false
        val selfClazz = chain[0].definingClass.name
        val interfaces = Scene.v().loadClass(selfClazz, SootClass.HIERARCHY).interfaces
        return "java.lang.Thread\$UncaughtExceptionHandler" in interfaces.map{ it.name }
    }

    private fun selfReachLambdaRunnable(chain: List<JMethod>): Boolean {
        val clz = chain[0].definingClass.shortName.startsWith("'-\$\$Lambda\$")
        val mtd = chain[0].methodName == "run"
        return clz && mtd
    }

    private val selfReachRunnable = SAMReacher("java.lang.Runnable", "run")
    private val selfReachCallable = SAMReacher("java.util.concurrent.Callable", "call")

    private fun SAMReacher(className: String, method: String):
                                            (List<JMethod>)->Boolean = body@ { chain ->
        fun isSubclass(clazz: SootClass?): Boolean {
            if(clazz == null)
                return false
            clazz.interfaces?.forEach{
                if(it.name == className)
                    return true
            }
            if(clazz.name?:"" == "java.lang.Object")
                return false    // no further subclasses
            return isSubclass(clazz.superclass)
        }
        if (chain[0].methodName != method)
            return@body false
        val selfClazz = chain[0].definingClass.name
        val clazz = Scene.v().loadClass(selfClazz, SootClass.HIERARCHY)
        return@body isSubclass(clazz)
    }

    private fun parentReachDummy(parent: JMethod): Boolean {
        val clazz = parent.definingClass.name
        val method = parent.methodName
        return (clazz=="dummyMainClass") || (clazz=="java.lang.Thread" && method=="start")
    }

    private fun parentReachSdk(parent: JMethod) = parent.isBlackList()

    private fun hasTryCatch(callChain: DCallChain): Boolean {
        for((callee, caller) in callChain.reversed().windowed(2, 1)){
            val crMethod = Scene.v().getMethod(caller)
            val ceMethod = Scene.v().getMethod(callee)
            val cfg = ExceptionalUnitGraph(crMethod.activeBody)
            for( (_, unit, invoke) in CFGUtil.findAllCallsites(crMethod) )
                if( invoke.method==ceMethod || invoke.methodRef==ceMethod )
                    if( cfg.getExceptionalSuccsOf(unit).isNotEmpty() )
                        return true
        }
        return false
    }

    fun removeWithTrycatch(dCallChains: Set<DCallChain>): Set<DCallChain> {
        return dCallChains.filter{ !hasTryCatch(it) }.toSet()
    }

}