package me.cirq.aper.util

import soot.SootMethod
import soot.Unit
import soot.Value
import soot.jimple.*
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG
import soot.toolkits.graph.*
import java.util.*


open class SootBodyUnitVisitor {
    open fun visitInvoke(invoke: InvokeExpr, unit: Unit) {}
    open fun visitArrayMemberAssign(lv: ArrayRef, rv: Value, unit: Unit) {}
}

open class SootBodyBlockVisitor {
    open fun visitInvoke(invoke: InvokeExpr, block: Block) {}
    open fun visitArrayMemberAssign(lv: ArrayRef, rv: Value, block: Block) {}
}

object CFGUtil {

    fun visitAllStmts(method: SootMethod, visitor: SootBodyUnitVisitor) {
        if(!method.hasActiveBody())
            return
        ExceptionalUnitGraph(method.activeBody!!)
                .filterIsInstance<Stmt>().forEach { unit ->
            if(unit.containsInvokeExpr()) {
                visitor.visitInvoke(unit.invokeExpr, unit)
            }
            if(unit is AssignStmt && unit.leftOp is ArrayRef) {
                visitor.visitArrayMemberAssign(unit.leftOp as ArrayRef, unit.rightOp, unit)
            }
        }
    }

    fun visitAllStmts(method: SootMethod, visitor: SootBodyBlockVisitor) {
        if(!method.hasActiveBody())
            return
        for(block in ExceptionalBlockGraph(method.activeBody!!)) {
            block.filterIsInstance<Stmt>().forEach {
                if(it.containsInvokeExpr()) {
                    visitor.visitInvoke(it.invokeExpr, block)
                }
                if(it is AssignStmt && it.leftOp is ArrayRef) {
                    visitor.visitArrayMemberAssign(it.leftOp as ArrayRef, it.rightOp, block)
                }
            }
        }
    }

    fun findAllCallsites(method: SootMethod) = iterator<Triple<Block,Unit,InvokeExpr>> {
        if (!method.hasActiveBody())
            return@iterator
        val cfg = ExceptionalBlockGraph(method.activeBody)
        for (block in cfg) {
            for (unit in block) {
                if (unit is Stmt && unit.containsInvokeExpr()) {
//                    if (unit is JInvokeStmt || unit is JAssignStmt)
                        yield(Triple(block, unit, unit.invokeExpr))
                }
            }
        }
    }

    fun findAllCallsites(block: Block) = iterator<Pair<Unit,InvokeExpr>> {
        for(unit in block) {
            if(unit is Stmt && unit.containsInvokeExpr()) {
                yield(Pair(unit, unit.invokeExpr))
            }
        }
    }

    // topological sort of block graph
    fun flowIterator(method: SootMethod) = iterator<Block> {
        if (!method.hasActiveBody())
            return@iterator
        val cfg = ExceptionalBlockGraph(method.activeBody)
        val inDeg = calcInDegreeWithoutBack(cfg)

        val visited = TreeSet<Int>()
        val queue = LinkedList(cfg.heads.map{ it.indexInMethod })
        while(queue.isNotEmpty()){
            val hidx = queue.removeFirst()
            check(inDeg[hidx] == 0)
            val head = cfg.blocks[hidx]
            yield(head)
            visited.add(hidx)
            head.succs.forEach{
                val idx = it.indexInMethod
                inDeg[idx] = inDeg[idx]!! - 1
//                if(it.isCatch() && inDeg[idx]!!>0) {
//                    // catch block should be visited when all its pres are visited
//                    return@forEach
//                }
//                if((idx !in visited) && (idx !in queue)) {
//                    // double check is essential
                if(inDeg[idx]!! == 0) {
                    queue.addLast(idx)
                }
            }
        }
        check(visited.size == cfg.blocks.size)  // there are no unvisited block
    }

    private fun calcInDegreeWithoutBack(cfg: BlockGraph): MutableMap<Int,Int> {
        require(cfg.heads.size == 1)

        val inMap = cfg.map{ it.indexInMethod to it.preds.size }.toMap().toMutableMap()

        // for eliminating back edges in control-flow graph
        // by Peng Ke
        fun dfs(u:Int, instk:MutableSet<Int>, vis:MutableSet<Int>){//, map:MutableMap<Int,Int>) {
            instk.add(u)
            vis.add(u)
            cfg.blocks[u].succs.map{it.indexInMethod}.forEach { v ->
                if(v in vis && v in instk) {
                    // (u,v) is a back edge
                    inMap[v] = inMap[v]!! - 1
                }
                else if(v !in vis) {
                    dfs(v, instk, vis)
                }
            }
            instk.remove(u)
        }
        dfs(cfg.heads.first().indexInMethod, HashSet(), HashSet())
        return inMap
    }

    fun getGraph(method: SootMethod): BlockGraph? {
        if (!method.hasActiveBody())
            return null
        return ExceptionalBlockGraph(method.activeBody)
    }

    fun getUnitGraph(method: SootMethod): UnitGraph? {
        if(!method.hasActiveBody())
            return null
        return ExceptionalUnitGraph(method.activeBody)
    }

    val icfg = JimpleBasedInterproceduralCFG()

}
