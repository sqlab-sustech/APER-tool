package me.cirq.aper.analyzer.step

import me.cirq.aper.HANDLE_API
import me.cirq.aper.entity.APermission
import me.cirq.aper.entity.DCallChain
import me.cirq.aper.entity.JMethod
import me.cirq.aper.util.isBlackList
import soot.Scene
import soot.SootClass
import soot.SootMethod
import java.util.*


/* The Step 4 */
object HandleStep {

    fun findHandleCallbacks(chain: DCallChain): Map<APermission,List<SootMethod>> {
        return chain.permissions.map {
            val handleSite: MutableSet<SootMethod> = LinkedHashSet()
            chain.forEach { method ->
                val handle = findMemberHandlesite(method, it)
                if(handle != null)
                    handleSite += handle
            }
            it to handleSite.toList()
        }.toMap()
    }

    private fun lastDefiningHandleClass(clazz: SootClass): SootClass {
        return when {
            clazz.name == "java.lang.Object" -> clazz
            clazz.declaresMethod(HANDLE_API) -> clazz
            else -> lastDefiningHandleClass(clazz.superclass)
        }
    }

    private fun findMemberHandlesite(method: JMethod, permission: APermission): SootMethod? {
        if(method.isBlackList())
            return null
        return try {
            val className = method.definingClass.toString()
            var clazz = Scene.v().loadClassAndSupport(className)
            clazz = lastDefiningHandleClass(clazz)
            clazz.getMethod(HANDLE_API)
        } catch (ex: Exception) {
            null
        }
    }

}
