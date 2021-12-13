package me.cirq.aper.analyzer

import me.cirq.aper.RUNNABLE_CLASS
import me.cirq.aper.analyzer.report.RevStepReport
import me.cirq.aper.analyzer.report.StepReport
import me.cirq.aper.entity.*
import me.cirq.aper.util.*
import soot.Scene
import soot.SootMethod


enum class HappenBeforeFollowType(private val desc: String) {
    NoDeclareAndNoSteps("No Declare And No Steps"),
    NoDeclareWithSteps("Not Declared But Has CHECK/REQUEST"),
    DeclaredNoSteps("Only Declared And No CHECK/REQUEST"),

    SyncCheckedAlready("Check Synchronously Already"),
    AsyncCheckBeforeUse("Check Asynchronously Before Use API"),
    NoAsyncCheckBeforeUse("No Asynchronous Check Before Use API"),
    IsHandleNoCheck("No Check Because Is Handle API"),

    SyncRequestedAlready("Request Synchronously Already"),
    AsyncRequestBeforeUse("Request Asynchronously Before Use API"),
    NoAsyncRequestBeforeUse("No Asynchronous Request Before Use API");

    override fun toString(): String {
        return "[${this.javaClass.simpleName}] $desc"
    }
}

private typealias HBFollowPair<T> = Pair<HappenBeforeFollowType,Set<T>?>

typealias HBFollowSituation<T> = Set<HBFollowPair<T>>


/**
 * Find whether developer follows assumption of looper execution order to ensure
 *  the permission is granted. Typically, `two` types of order are considered:
 *      + Android application lifecycle
 *      + Runnable/Callable posting location
 *
 * Termly, called the "Asynchronous happened-before analysis"
 */

object HappenBeforeAnalyzer {

    private object HappenBeforeRecorder {
        // values should happen before key
        val happen_before: MutableMap<JMethod,MutableSet<JMethod>> = HashMap()

        fun put(method: JMethod, hbMethod: JMethod) {
            if(method !in happen_before)
                happen_before[method] = HashSet()
            happen_before[method]!!.add(hbMethod)
        }

        fun get(method: JMethod): Set<JMethod> {
            if(method !in happen_before)
                happen_before[method] = HashSet()
            return happen_before[method]!!
        }
    }

    // indicate the predicate "this happens before that"
    private infix fun JMethod.hb(that: JMethod): Boolean {
        if(that !in HappenBeforeRecorder.happen_before)
            HappenBeforeRecorder.happen_before[that] = HashSet()
        return this in HappenBeforeRecorder.happen_before[that]!!
    }



    fun asynchronousAnalyze(reports: Set<StepReport>,
                            revreports: RevStepReport,
                            dump: Boolean=false): Map<String,HBFollowSituation<ACallChain>> {
        val asyncReport = HashMap<String,HBFollowSituation<ACallChain>>()
        reports.forEach{ report ->
            val needs = report.permissionReports.keys
            val declared = report.permissionReports.filter{ it.key in needs }
                                                   .map{ it.key to it.value.isDeclared }
                                                   .toMap()
            val syncChecked = report.permissionReports.values.any{ it.checkSites.isNotEmpty() }
            val syncRequested = report.permissionReports.values.any{ it.requestSites.isNotEmpty() }
            val checks = revreports.checkMap.values
                                   .flatten().filter{ needs.intersect(it.permissions).isNotEmpty() }
            val requests = revreports.requestMap.values
                                     .flatten().filter{ needs.intersect(it.permissions).isNotEmpty() }
//                                     .flatten().filter{ when(PermissionCombination.get(report.api)) {
//                                                           // either one in needs is ok
//                                                           AnyOf -> needs.intersect(it.permissions).isNotEmpty()
//                                                           AllOf -> needs.union(it.permissions).size==needs.size
//                                                      } }
            val key = report.storePath.toString()
            val ft = analyzeFollowType(report.chain, declared, checks, requests, syncChecked, syncRequested)
            asyncReport[key] = ft
        }
        if(dump) {
            val r = asyncReport.map{ (path, types) ->
                val result = types.map{ (type, chain) ->
                    chain?.joinToString("\n\t", "$type\n\t"){
                        it.joinToString(" -> ")
                    } ?: type
                }.joinToString("\n---\n", "\n---\n", "\n\n")
                path+result
            }
            FileUtil.writeListTo(r, "asyncreport.txt")
        }
        return asyncReport
    }

    private fun analyzeFollowType(chain: List<JMethod>,
                                  declared: Map<APermission,Boolean>,
                                  checks: List<PCallChain>,
                                  requests: List<PCallChain>,
                                  syncChecked: Boolean,
                                  syncRequested: Boolean): HBFollowSituation<ACallChain> {
        if(declared.isEmpty()){
            return if(checks.isEmpty() && requests.isEmpty())
                setOf(Pair(HappenBeforeFollowType.NoDeclareAndNoSteps,null))
            else
                setOf(Pair(HappenBeforeFollowType.NoDeclareWithSteps,null))
        }
        else if(checks.isEmpty() && requests.isEmpty()){
            return setOf(Pair(HappenBeforeFollowType.DeclaredNoSteps,null))
        }

        val types = HashMap<HappenBeforeFollowType,MutableSet<ACallChain>?>()

        if(syncChecked) {
            types[HappenBeforeFollowType.SyncCheckedAlready] = HashSet()
        }
        else if(chain.first().isHandleApi()) {
            types[HappenBeforeFollowType.IsHandleNoCheck] = HashSet()
        }
        else {
            checks.forEach {
                if (it.chain canHappenBefore chain) {
                    if (HappenBeforeFollowType.AsyncCheckBeforeUse !in types)
                        types[HappenBeforeFollowType.AsyncCheckBeforeUse] = HashSet()
                    types[HappenBeforeFollowType.AsyncCheckBeforeUse]!!.add(it)
                }
            }
            if (HappenBeforeFollowType.AsyncCheckBeforeUse !in types) {
                types[HappenBeforeFollowType.NoAsyncCheckBeforeUse] = null
            }
        }

        if(syncRequested) {
            types[HappenBeforeFollowType.SyncRequestedAlready] = HashSet()
        }
        else {
            // obviously, the permission is requested thus HANDLE is invoked
            if (chain.first().isHandleApi()) {
                if (HappenBeforeFollowType.AsyncRequestBeforeUse !in types)
                    types[HappenBeforeFollowType.AsyncRequestBeforeUse] = HashSet()
            }
            for(it in requests) {
                if (it.chain canHappenBefore chain) {
                    if(chain.first().isHandleApi() && !fromTheSameComponent(chain.first(), it.chain.first()))
                        continue
                    if (HappenBeforeFollowType.AsyncRequestBeforeUse !in types)
                        types[HappenBeforeFollowType.AsyncRequestBeforeUse] = HashSet()
                    types[HappenBeforeFollowType.AsyncRequestBeforeUse]!!.add(it)
                }
            }
            if (HappenBeforeFollowType.AsyncRequestBeforeUse !in types) {
                types[HappenBeforeFollowType.NoAsyncRequestBeforeUse] = null
            }
        }

        return types.map{ (k,v) -> Pair(k,v) }.toSet()
    }

    private fun fromTheSameComponent(ma: JMethod, mb: JMethod): Boolean {
        val ca = ma.definingClass.outterClass()
        val cb = mb.definingClass.outterClass()
        return ca == cb
    }


    private val mcg: Map<JClass,Set<JClass>> by lazy {
        ModuleCGAnalyzer.getModuleCG()
    }

    private infix fun List<JMethod>.canHappenBefore(that: List<JMethod>): Boolean {
        // `this` must be a permission maintaining chain
        val thisClass = this[0].definingClass.outterClass()
        val thatClass = that[0].definingClass.outterClass()

        if(thisClass != thatClass) {
            if(thisClass.isComponent() && thatClass.isComponent()){
                // happen-before by ICC-graph
                return (thisClass in mcg) && (thatClass in mcg.getValue(thisClass))
            }
            else if(thisClass.isApplication() || thatClass.isApplication()) {
                check(thisClass.isNotApplication() || thatClass.isNotApplication())
                // the case when only one is application
                return thisClass.isApplication() && thatClass.isNotApplication()
            }
            else if(thisClass.isComponent() && thatClass.isNotComponent()) {
                return false    // for under-estimate
            }
            else if(thisClass.isNotComponent() && thatClass.isComponent()) {
                return false
            }
            else {
                assert(thisClass.isNotComponent() && thatClass.isNotComponent())    // dummy assert
                return false
            }
        }
        else {  // same outter class, analyze by flowdroid dummyMain
            val thisSootMethod = Scene.v().getMethod(this[0].sootSignature)
            val thatSootMethod = Scene.v().getMethod(that[0].sootSignature)
            if(thisSootMethod == thatSootMethod)
                return false    // same class, same method, synchronous

            else if(this[0].definingClass != that[0].definingClass){
                // in case of anonymous class
                val thatInnerClass = Scene.v().getSootClass(that[0].definingClass.name)
                return thisClass.isComponent() &&
                        RUNNABLE_CLASS in thatInnerClass.interfaces &&
                        thatSootMethod.name == "run"
            }
            return thisClass.isComponent() &&
                    thisSootMethod lifecycleHappenBefore thatSootMethod
        }
    }

//    private fun JClass.isComponent() = (this.name.substringBefore("$") in ModuleCGAnalyzer.cmpNames)
    private fun JClass.isComponent() = (this.name in ModuleCGAnalyzer.cmpNames)
    private fun JClass.isNotComponent() = !this.isComponent()

    private fun JClass.isApplication() = this == ManifestAnalyzer.applicationClass
    private fun JClass.isNotApplication() = !this.isApplication()


    private infix fun SootMethod.lifecycleHappenBefore(that: SootMethod): Boolean {
        val dummyMain = "dummyMainClass: ${this.declaringClass}"

        val thisParent = CGUtil.getCallTo(this).uniqueToList{ it.signature.contains(dummyMain) }
        val thatParent = CGUtil.getCallTo(that).uniqueToList{ it.signature.contains(dummyMain) }
        if(thisParent.isEmpty() || thatParent.isEmpty())
            return false
        require(thisParent.size==1 && thatParent.size==1)

        val thisDummy = thisParent[0]
        val thatDummy = thatParent[0]
        require(thisDummy.signature == thatDummy.signature)

        val thisJmethod = JMethod.fromSootSignature(this.signature)
        val thatJmethod = JMethod.fromSootSignature(that.signature)
        return thisJmethod lifecycleHappenBefore thatJmethod
//        var thisInvoked = false
//        CFGUtil.flowIterator(thisDummy).forEach { block ->
//            CFGUtil.findAllCallsites(block).forEach { (_, invoke) ->
//                if(invoke.method.signature == this.signature)
//                    thisInvoked = true
//                else if(invoke.method.signature==that.signature && thisInvoked)
//                    return true
//            }
//        }
//        return false
    }

    private fun JClass.outterClass(): JClass {
        val name = this.name.substringBefore('$')
        return JClass(name)
    }



    private infix fun JMethod.lifecycleHappenBefore(that: JMethod): Boolean {
        require(this.definingClass.outterClass() == that.definingClass.outterClass())
        val thisIndex = COMPONENT_LIFECYCLE.indexOf(this.methodName)
        val thatIndex  = COMPONENT_LIFECYCLE.indexOf(that.methodName)

        return if(thisIndex < 0 && thatIndex < 0)
            true
        else if(thisIndex < 0 && thatIndex >= 0)
            thatIndex > APP_METHOD  // that is in later half
        else if(thisIndex >= 0 && thatIndex < 0)
            thisIndex < APP_METHOD
        else
            thisIndex < thatIndex
    }
    private val COMPONENT_LIFECYCLE = listOf(
            "onCreate",
            "onRestart",
            "onStart",
            "onResume",
            // any other methods
            "onPause",
            "onStop",
            "onDestroy"
    )
    private val APP_METHOD = COMPONENT_LIFECYCLE.indexOf("onResume") + 0.5
}
