package me.cirq.aper.transformer

import me.cirq.aper.util.CFGUtil
import me.cirq.aper.util.LogUtil
import me.cirq.aper.util.isHandleApi
import soot.Body
import soot.BodyTransformer
import soot.Local
import soot.SootMethod
import soot.Unit
import soot.jimple.Stmt
import soot.toolkits.scalar.LocalDefs
import soot.toolkits.scalar.SimpleLocalDefs
import java.util.*


class HandleRdTransformer: BodyTransformer() {

    companion object {
        private val defs = HashMap<SootMethod,LocalDefs>()

        fun handleRdFactAt(method: SootMethod, local: Local, stmt: Stmt): List<Unit> {
            require(method.isHandleApi())
            return defs[method]!!.getDefsOfAt(local, stmt)
        }
    }


    override fun internalTransform(body: Body, phase: String, options: MutableMap<String, String>) {
        val method = body.method
        if(!method.isHandleApi())
            return
        LogUtil.info(this, "start reaching-definition at handle ${method.declaringClass}")

        val graph = CFGUtil.getUnitGraph(method)
        defs[method] = SimpleLocalDefs(graph)
    }

}
