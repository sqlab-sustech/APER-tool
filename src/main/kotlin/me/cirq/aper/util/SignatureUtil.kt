package me.cirq.aper.util

import soot.SootMethod
import soot.jimple.InvokeStmt


val moduleInteractionMethodNames = setOf(
        "startActivity",
        "startActivityForResult",
        "startActivityFromChild",
        "startActivityFromFragment",
        "startActivityIfNeeded",
        "startService",
        "bindService",
        "startForegroundService",
        "sendBroadcast",
        "sendBroadcastAsUser",
        "sendOrderedBroadcast",
        "sendOrderedBroadcastAsUser",
        "sendStickyBroadcast",
        "sendStickyBroadcastAsUser",
        "sendStickyOrderedBroadcast",
        "sendStickyOrderedBroadcastAsUser"
)

/**
 * Data class to store the parsed signature result
 * @property isBCReceiver If this is a API for register a BroadCast Receiver
 * @property identifier The identifier name for corresponding Intent argument
 * @property apiName The name for API called in this stmt
 */
data class SigParseResult(
        val isBCReceiver: Boolean,
        val identifier: String,
        val apiName: String
)

fun SootMethod.isModuleInteractionMethod() = this.name in moduleInteractionMethodNames
fun SootMethod.isAndroidContext(): Boolean {
    var parentClass = this.declaringClass
    while (parentClass.hasSuperclass()) {
        if (parentClass.name == "android.content.Context") {
            return true
        }
        parentClass = parentClass.superclass
    }
    return false
}

/**
 * Util class to parse a stmt method signature
 */
object SignatureUtil{
    /**
     * Parse the called API to get the identifier for Intent argument
     * @param stmt Statement to be parsed
     * @return Parsed result
     */
    fun parseIntentArg(stmt: InvokeStmt): SigParseResult? {
        //TODO: handle list of Intent

        val method = stmt.invokeExpr.method
//        if (!method.isAndroidContext()) {
//            if (method.isModuleInteractionMethod()) {
//                LogUtil.debug(this, "${method.name} is not passed")
//            }
//            return null
//        }

        val args = stmt.invokeExpr.args

        /* Check if this is an API for registering broadcast receiver*/
        if (method.name == "registerReceiver" && args.size >= 2 && args[1].type.toString() == "android.content.IntentFilter") {
            return SigParseResult(true, args[1].toString(), method.name)
        }

        /* Check if this is an API for start Activity, Service, BroadCast */
        if (method.isModuleInteractionMethod()) {
            try {
                val index = args.single { it.type.toString() == "android.content.Intent" }.toString()
                return SigParseResult(false, index, method.name)
            } catch (e: Exception) {
                LogUtil.error(this, "Can't find Intent parameter in ${method.name}")
            }
        }

        return null
    }
}
