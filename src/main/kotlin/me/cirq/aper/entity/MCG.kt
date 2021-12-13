package me.cirq.aper.entity

import me.cirq.aper.util.baseName
import soot.SootMethod
import soot.Unit
import soot.jimple.AssignStmt
import soot.jimple.InvokeExpr
import soot.jimple.InvokeStmt
import java.util.*


data class CallerMethod(
        val callerUnit: Unit,
        val callerMethod: SootMethod
)


data class Edge(
        var inCmp: String,
        var apiName: String,
        var intent: Intent,
        var outCmp: String?
)


data class Receiver(
        val name: String,
        val intentFilter: List<IntentFilter>
) {
    fun match(intent: Intent): Boolean {
        return intentFilter.any { it.matchIntent(intent) }
    }
}


class Activity(
        val name: String,
        val intentFilter: List<IntentFilter>
) {
    fun match(intent: Intent): Boolean {
        return intentFilter.any { it.matchIntent(intent) }
    }
}


data class ActivityAlias(
        val name: String,
        val targetActivity: String,
        val intentFilter: List<IntentFilter>
)


data class Provider(
        val name: String
)


class Service(
        val name: String,
        val intentFilter: List<IntentFilter>
) {
    fun match(intent: Intent): Boolean {
        return intentFilter.any { it.matchIntent(intent) }
    }
}



class ComponentName constructor(curParamName: String, methodStack: ArrayDeque<CallerMethod>) : SuperIntent(curParamName, methodStack) {
    lateinit var name: String
    override fun isSelfDefined(className: String): Boolean = className != "android.content.ComponentName"
    private val callingAPI = arrayOf("createRelative")

    override fun resolveCallingAPI(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        this.curParamName = expr.baseName()
        when (expr.method.name) {
            "createRelative" -> {
                this.name = expr.getArg(1).toString()
            }
        }
    }

    override fun resolveInit(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        val args = expr.args
        when (args.size) {
            2 -> {
                this.name = args.get(1).toString()
            }
        }
    }

    override fun resolveInvokeExpr(invokeStmt: InvokeStmt, sootMethod: SootMethod) {
        super.resolveInvokeExpr(invokeStmt, sootMethod)
        val expr = invokeStmt.invokeExpr
        when (expr.method.name) {
            "<init>" -> {
                resolveInit(expr, invokeStmt, sootMethod)
                this.findDef = true
            }
            in callingAPI -> {
                resolveCallingAPI(expr, invokeStmt, sootMethod)
            }
        }
    }

    override fun resolveAssignExpr(assignStmt: AssignStmt, sootMethod: SootMethod) {
        super.resolveAssignExpr(assignStmt, sootMethod)
        val expr: InvokeExpr = assignStmt.invokeExpr
        when (expr.method.name) {
            in callingAPI -> {
                resolveCallingAPI(expr, assignStmt, sootMethod)
            }
        }
    }
}



class Uri constructor(curParamName: String, methodStack: ArrayDeque<CallerMethod>) : SuperIntent(curParamName, methodStack) {
    private val callingAPI = arrayOf("")
    var rawString: String = ""
    var scheme: String = ""
    var ssp: String = ""
    var authority: String = ""
    var userInfo: String = ""
    var host: String = ""
    var port = ""
    var path = ""
    var query = ""
    var fragment = ""

    override fun isSelfDefined(className: String): Boolean = className != "android.net.Uri"

    override fun resolveCallingAPI(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
    }

    fun parseStringUri(uri: String) {
        this.rawString = uri
        val uriData = parse(uri)
        scheme = uriData.scheme
        ssp = uriData.ssp
        authority = uriData.auth
        host = uriData.host
        port = uriData.port
        path = uriData.path
        fragment = uriData.fragment
    }

    override fun resolveInit(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
//        val args = expr.args
//        when(args.size){
//            1 -> parseStringUri(args.get(0).getValue())
//            3 -> {
//                scheme = args.get(0).getValue()
//                ssp = args.get(1).getValue()
//                fragment = args.get(2).getValue()
//            }
//            4 -> {
//                scheme = args.get(0).getValue()
//                host = args.get(1).getValue()
//                path = args.get(2).getValue()
//                fragment = args.get(3).getValue()
//            }
//            5 -> {
//                scheme = args.get(0).getValue()
//                authority = args.get(1).getValue()
//                path = args.get(2).getValue()
//                query = args.get(3).getValue()
//                fragment = args.get(4).getValue()
//            }
//            7 -> {
//                scheme = args.get(0).getValue()
//                userInfo = args.get(1).getValue()
//                host = args.get(2).getValue()
//                port = args.get(3).getValue()
//                path = args.get(4).getValue()
//                query = args.get(5).getValue()
//                fragment = args.get(6).getValue()
//            }
//        }
    }

    override fun resolveAssignExpr(assignStmt: AssignStmt, sootMethod: SootMethod) {
        super.resolveAssignExpr(assignStmt, sootMethod)
        val expr: InvokeExpr = assignStmt.invokeExpr
        when (expr.method.name) {
            in arrayOf("create", "parse") -> {
                parseStringUri(expr.getArg(0).toString())
                this.findDef = true
            }
            "fromParts" -> {
                val scheme = expr.getArg(0).toString()
                val ssp = expr.getArg(1).toString()
                val fragment = expr.getArg(2).toString()
                parseStringUri("${scheme}:${ssp}#${fragment}")

            }
            in callingAPI -> {
                resolveCallingAPI(expr, assignStmt, sootMethod)
            }
        }
    }

    override fun resolveInvokeExpr(invokeStmt: InvokeStmt, sootMethod: SootMethod) {
        super.resolveInvokeExpr(invokeStmt, sootMethod)
        val expr = invokeStmt.invokeExpr
        when (expr.method.name) {
            "<init>" -> {
                resolveInit(expr, invokeStmt, sootMethod)
                this.findDef = true
            }
            in callingAPI -> {
                resolveCallingAPI(expr, invokeStmt, sootMethod)
            }
        }
    }
}



data class UriData(
        val scheme: String,
        val ssp: String,
        val auth: String,
        val path: String,
        val host: String,
        val port: String,
        val fragment: String
)


fun parse(string: String): UriData {
    val scheme = string.substringBefore(":")
    val fragment = string.substringAfter("#", "")
    val ssp = string.substringAfter(":", "").substringBefore("#")
    val authPath = ssp.substringBefore("?")
    val auth = authPath.substringAfter("//").substringBefore("/")
    val path = authPath.substringAfter("//", "").substringAfter("/", "")
    val host = auth.substringBefore(":")
    val port = auth.substringAfter(":", "")
    return UriData(scheme, ssp, auth, path, host, port, fragment)
}
