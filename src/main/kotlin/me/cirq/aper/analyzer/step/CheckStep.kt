package me.cirq.aper.analyzer.step

import me.cirq.aper.CHECK_APIS
import me.cirq.aper.Config
import me.cirq.aper.analyzer.MethodAnalyzer
import me.cirq.aper.entity.*
import me.cirq.aper.transformer.StringAnalysisTransformer
import me.cirq.aper.util.*
import soot.Scene
import soot.SootMethod
import soot.Unit
import soot.Value
import soot.jimple.InvokeExpr
import soot.jimple.StringConstant
import soot.jimple.internal.JimpleLocal
import java.util.*


// check as `unit` eventually invoked by `method` at the `int`-th call chain element
typealias CheckSite = Quadruple<Int,SootMethod,Unit,InvokeExpr>

private typealias UnindexCheckSite = Triple<SootMethod,Unit,InvokeExpr>


/* The Step 2 */
object CheckStep {

    fun findAllChecksites(chain: DCallChain): Map<APermission,List<CheckSite>> {
        val checkBlock: MutableMap<APermission, List<CheckSite>> = HashMap()
        for(permission in chain.permissions) {
            val checkSite: MutableList<CheckSite> = LinkedList()
            val visited: MutableSet<SootMethod> = HashSet()
            chain.take(chain.chainSize-1).withIndex().forEach{ (i, method) ->
                val sootMethod = Scene.v().getMethod(method)
                val exceptMethod = Scene.v().getMethod(chain[i+1])
                val set: MutableSet<UnindexCheckSite> = LinkedHashSet()
                checksites(LinkedList(listOf(sootMethod)),
                           permission, exceptMethod, visited, set, Config.get().exLengthThreshold)
                checkSite += set.map{ Quadruple(i, it.first, it.second, it.third) }
            }
            checkBlock[permission] = checkSite
        }
        return checkBlock
    }


    // recursive call to expand trace
    private fun checksites(stack: LinkedList<SootMethod>,
                           permission: APermission,
                           except: SootMethod,
                           visited: MutableSet<SootMethod>,
                           sites: MutableSet<UnindexCheckSite>,
                           level: Int) {
        if(level == 0) // level in cluding method itself
            return
        checksitesInMethod(stack, permission, sites)
        val method = stack.last()
        visited += method
        CGUtil.getCISCallFrom(method).except(except).forEach { child ->
            if(child in visited)
                return@forEach
            if(child.isBlackList())
                return@forEach
            stack.addLast(child)
            checksites(stack, permission, except, visited, sites, level-1)
            stack.removeLast()
        }
    }

    private fun checksitesInMethod(stack: LinkedList<SootMethod>,
                                   permission: APermission,
                                   sites: MutableSet<UnindexCheckSite>) {
        CFGUtil.visitAllStmts(stack.last(), object: SootBodyUnitVisitor(){
            override fun visitInvoke(invoke: InvokeExpr, unit: Unit) {
//                val calleeRef = invoke.methodRef.signature  // the method that called
//                val callee = invoke.method.signature        // the actual method that called (the actual override)
                val sootSig = invoke.method.signature
                if(sootSig in CHECK_APIS) {
                    val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(unit)
                    if(permission in saPermission) {
                        val checker = if(stack.size==1) Scene.v().getMethod(sootSig)
                                      else stack[1]   // todo: the one that directly expanded from call chain, maybe wrong
                        val triple = Triple(checker, unit, invoke)
                        sites.add(triple)
                    }
//                    invoke.args.filter{ isValidArgument(it, permission) }
//                               .takeIf{ it.isNotEmpty() }
//                              ?.let{
//                                  check(it.size==1 && it[0] is StringConstant)
//                                  val checker = if(stack.size==1) Scene.v().getMethod(sootSig)
//                                                else stack[1]
//                                  sites.add(Triple(checker, unit, invoke)) }
                }
            }
        })
    }

    @Deprecated("use strana algorithm instead")
    private fun isValidArgument(value: Value, permission: APermission): Boolean {

        val validType = value.type.toString() == "java.lang.String"

        val validValue = when(value) {
            is StringConstant -> true//value.value.toString() == permission.toString()
            is JimpleLocal -> false // no further dataflow analysis
            else -> false
        }

        return validType && validValue
    }










    fun getCheckCallchains(): Set<PCallChain> {
        val checkChains: MutableSet<PCallChain> = HashSet()
        CHECK_APIS.forEach {
            val method = JMethod.fromSootSignature(it)
            MethodAnalyzer.collectCallchainsTo(method) { chain ->
                val chk = chain.last().sootSignature
                val checker = Scene.v().getMethod(chain.last(2))
                CFGUtil.visitAllStmts(checker, object: SootBodyUnitVisitor(){
                    override fun visitInvoke(invoke: InvokeExpr, unit: Unit) {
                        if(invoke.method.signature == chk) {
//                            val permission = findValidArgument(invoke.args)
                            val saPermission = StringAnalysisTransformer.concretePermissionValuesAt(unit)
                            checkChains += PCallChain(chain, saPermission)
                        }
                    }
                })
            }
        }
        return checkChains
    }

    @Deprecated("use strana algorithm instead")
    private fun findValidArgument(args: List<Value>): APermission? {
        val filter: (Value)->Boolean = { v -> v.type.toString()=="java.lang.String" }

        return when(val pValue = args.first(filter)) {
            is StringConstant -> APermission(pValue.value.toString())
            is JimpleLocal -> null
            else -> null
        }
    }

}
