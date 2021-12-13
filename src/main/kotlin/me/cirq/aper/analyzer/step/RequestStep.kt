package me.cirq.aper.analyzer.step

import me.cirq.aper.Config
import me.cirq.aper.REQUEST_APIS
import me.cirq.aper.analyzer.MethodAnalyzer
import me.cirq.aper.entity.*
import me.cirq.aper.transformer.StringAnalysisTransformer
import me.cirq.aper.util.*
import soot.Scene
import soot.SootMethod
import soot.Unit
import soot.Value
import soot.jimple.ArrayRef
import soot.jimple.InvokeExpr
import soot.jimple.StringConstant
import soot.jimple.internal.JimpleLocal
import soot.toolkits.graph.Block
import java.util.*


// similar to CheckSite
typealias RequestSite = Quadruple<Int,SootMethod,Unit,InvokeExpr>

private typealias UnindexRequestSite = Triple<SootMethod,Unit,InvokeExpr>


/* The Step 3 */
object RequestStep {

    fun findAllRequestsites(chain: DCallChain): Map<APermission,List<RequestSite>> {
        val requestBlock: MutableMap<APermission, List<RequestSite>> = HashMap()
        for(permission in chain.permissions) {
            val requestSite: MutableList<RequestSite> = LinkedList()
            val visited: MutableSet<SootMethod> = HashSet()
            chain.take(chain.chainSize-1).withIndex().forEach{ (i, method) ->
                val sootMethod = Scene.v().getMethod(method)
                val exceptMethod = Scene.v().getMethod(chain[i+1])
                val set: MutableSet<UnindexRequestSite> = LinkedHashSet()
                requestsites(LinkedList(listOf(sootMethod)),
                             permission, exceptMethod, visited, set, Config.get().exLengthThreshold)
                requestSite += set.map{ Quadruple(i, it.first, it.second, it.third) }
            }
            requestBlock[permission] = requestSite
        }
        return requestBlock
    }


    private fun requestsites(stack: LinkedList<SootMethod>,
                             permission: APermission,
                             except: SootMethod,
                             visited: MutableSet<SootMethod>,
                             sites: MutableSet<UnindexRequestSite>,
                             level: Int) {
        if(level == 0) // level in cluding method itself
            return
        requestsitesInMethod(stack, permission, sites)
        val method = stack.last()
        visited += method
        CGUtil.getCISCallFrom(method).except(except).forEach { child ->
            if(child in visited)
                return@forEach
            if(child.isBlackList())
                return@forEach
            stack.addLast(child)
            requestsites(stack, permission, except, visited, sites, level-1)
            stack.removeLast()
        }
    }

    // for use like latestDefOf["$r2"]["0"] == "android.permission.READ_EXTERNAL_STORAGE"
    private val latestDefOf: MutableMap<String,MutableMap<String,Value>> = HashMap()

    private fun requestsitesInMethod(stack: LinkedList<SootMethod>,
                                     permission: APermission,
                                     sites: MutableSet<UnindexRequestSite>) {
//        latestDefOf.clear() // method wild
        CFGUtil.visitAllStmts(stack.last(), object: SootBodyUnitVisitor(){
            override fun visitInvoke(invoke: InvokeExpr, unit: Unit) {
                val sootSig = invoke.method.signature
                if(sootSig in REQUEST_APIS) {
                    val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(unit)
                    if(permission in saPermission) {
                        val requester = if(stack.size==1) Scene.v().getMethod(sootSig)
                                        else stack[1]   // todo: the one that directly expanded from call chain, maybe wrong
                        val triple = Triple(requester, unit, invoke)
                        sites.add(triple)
                    }
//                    invoke.args.filter{ isValidArgument(it, permission) }
//                               .takeIf{ it.isNotEmpty() }
//                              ?.let{
//                                  val requester = if(stack.size==1) Scene.v().getMethod(sootSig)
//                                                  else stack[1]
//                                  check(it.size==1 && it[0] is JimpleLocal)
//                                  val arr = latestDefOf[it[0].toString()]!!.values
//                                  sites.add(Triple(requester, unit, invoke)) }
                }
            }
//            override fun visitArrayMemberAssign(lv: ArrayRef, rv: Value, block: Block) {
//                if(rv is StringConstant) {
//                    val base = lv.base.toString()
//                    val index = lv.index.toString()
//                    if(base !in latestDefOf)
//                        latestDefOf[base] = HashMap()
//                    latestDefOf[base]!![index] = rv
//                }
//                if(rv is JimpleLocal) {
//                    // no further dataflow analysis
//                }
//            }
        })
    }

    @Deprecated("use strana algorithm instead")
    private fun isValidArgument(value: Value, permission: APermission): Boolean {

        val validType = value.type.toString() == "java.lang.String[]"

        val validValue = Pair(value, permission).let { (v, p) ->
            if(v is JimpleLocal) {
                return@let latestDefOf[v.toString()]?.values
                                                ?.notvoid()
//                                                ?.contains(p.toString())
            }
            return@let false
        }?:false

        return validType && validValue
    }













    fun getRequestCallchains(): Set<PCallChain> {
        val requestChains: MutableSet<PCallChain> = HashSet()
        REQUEST_APIS.forEach {
            val method = JMethod.fromSootSignature(it)
            MethodAnalyzer.collectCallchainsTo(method) { chain ->
                val req = chain.last().sootSignature
                val requester = Scene.v().getMethod(chain.last(2))
                latestDefOf.clear() // method wild
                CFGUtil.visitAllStmts(requester, object: SootBodyUnitVisitor(){
//                    override fun visitArrayMemberAssign(lv: ArrayRef, rv: Value, unit: Unit) {
//                        if(rv is StringConstant) {  // usage of latestDefOf
//                            val base = lv.base.toString()
//                            val index = lv.index.toString()
//                            if(base !in latestDefOf)
//                                latestDefOf[base] = hashMapOf<String,Value>(index to rv)
//                            else
//                                latestDefOf[base]!![index] = rv
//                        }
////                        if(rv is JimpleLocal) {
////                            // no further dataflow analysis
////                        }
//                    }
                    override fun visitInvoke(invoke: InvokeExpr, unit: Unit) {
                        if(invoke.method.signature == req) {
//                            val permissions = findValidArgument(invoke.args)
                            val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(unit)
                            requestChains += PCallChain(chain, saPermission)
                        }
                    }
                })
            }
        }
        return requestChains
    }

    @Deprecated("use strnan algorithm instead")
    private fun findValidArgument(args: List<Value>): List<APermission>? {
        val filter: (Value)->Boolean = { v -> v.type.toString()=="java.lang.String[]" }

        val pValues: List<IndexedString> = args.first(filter).let {
            if(it is JimpleLocal) {
                return@let latestDefOf[it.toString()]?.map{ (i, v) ->
                    Pair(i.toInt(), v)
                }
            }
            return@let null
        }?: return null

        return pValues.sortedBy{ it.first }
                      .map{ APermission((it.second as StringConstant).value.toString()) }
                      .toList()
    }

}

private typealias IndexedString = Pair<Int,Value>
