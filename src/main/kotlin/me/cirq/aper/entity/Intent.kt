package me.cirq.aper.entity

import me.cirq.aper.util.LogUtil
import me.cirq.aper.util.baseName
import soot.*
import soot.Unit
import soot.jimple.*
import soot.jimple.internal.JimpleLocal
import java.util.*
import kotlin.collections.HashSet


val UNCHANGEAPI = arrayOf("addFlags", "getSelector", "parseIntent", "putExtra",
        "putCharSequenceArrayListExtra", "putIntegerArrayListExtra", "replaceExtras", "setFlags", "setIdentifier", "setPackage")



data class IntentAction(val name: String="")


data class IntentCategory(val name: String="")


data class IntentType(val name: String="")


class IntentData(var scheme: String = "",
                 var host: String = "",
                 var port: String = "",
                 var path: String = "",
                 var pathPattern: String = "",
                 var pathPrefix: String = "",
                 var mimeType: String = "" ) {
    fun getAuthority(): String {
        // Fixme
        return "${host}:${port}"
    }

    fun hasAuthority(): Boolean = this.host != "" || this.port != ""

    fun hasPath(): Boolean = this.path != ""

    fun hasScheme(): Boolean = this.scheme != ""

    fun hasType(): Boolean = this.mimeType != ""
    private fun matchScheme(intent: Intent): Boolean {
        var special = false
        if (hasUri() && intent.data.hasUri() && hasType() && intent.type.name != "") {
            special = intent.type.name in arrayOf("content", "file")
        }
        return (scheme == intent.data.scheme) || intent.data.scheme == "" || special
    }

    private fun matchAuthority(intent: Intent): Boolean =
            getAuthority() == intent.data.getAuthority() && getAuthority() != ":" || intent.data.getAuthority() == ":"

    private fun matchPath(intent: Intent): Boolean =
            path == intent.data.path && path != ""

    fun matchType(intent: Intent): Boolean {
        if (!hasType()) {
            return intent.type.name != ""
        }
        try {
            return intent.type.name.contains(Regex(mimeType.checkType()))
        } catch (e: Exception) {
            print("")
        }
        return false
    }

    fun match(intent: Intent): Boolean {
        LogUtil.debug(this, "Start matching data!")
        return matchUri(intent) && matchType(intent)
    }

    fun hasUri(): Boolean = this.hasScheme()

    fun matchUri(intent: Intent): Boolean {
        LogUtil.debug(this, "Start matching Uri.")
        var schemeR = false
        var authorityR = false
        var pathR = false
        /*
        * If do not have Uri, return if intent has Uri
        */
        if (!hasUri()) {
            LogUtil.debug(this, "This data doesn't has Uri.")
            return !intent.data.hasUri()
        }
        if (hasScheme()) {
            schemeR = matchScheme(intent)
        }
        if (hasAuthority()) {
            authorityR = matchAuthority(intent)
        }
        if (hasPath()) {
            pathR = matchPath(intent)
        }
        LogUtil.debug(this, "This data has Uri. Match result: ")
        LogUtil.debug(this, "${scheme}, ${intent.data.scheme} -> ${schemeR}")
        LogUtil.debug(this, "${getAuthority()}, ${intent.data.getAuthority()} -> ${authorityR}")
        LogUtil.debug(this, "${path}, ${intent.data.path} -> ${pathR}")

        return schemeR && authorityR && pathR
    }

    private fun String.checkType(): String =
            if (this.startsWith("*")) "." + this else this
}


abstract class SuperIntent(var curParamName: String?, protected val methodStack: ArrayDeque<CallerMethod>) {
    var findDef: Boolean = false
    open fun resolveInvokeExpr(invokeStmt: InvokeStmt, sootMethod: SootMethod) {

        LogUtil.debug(this, "Resolving invoke API: ${invokeStmt.invokeExpr.method.name}")
    }

    open fun resolveAssignExpr(assignStmt: AssignStmt, sootMethod: SootMethod) {
        LogUtil.debug(this, "Resolve assign API ${assignStmt.invokeExpr.method.name}")
    }

    /**
     * Resolve <init> function
     * @param <init> expr
     */
    abstract fun resolveInit(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod)

    /**
     * Resolve the APIs called by Intent object
     * @param expr Expr that contains called API
     */
    abstract fun resolveCallingAPI(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod)

    private fun resolveCallerPassed(position: Int) {
        if (methodStack.isEmpty()) return
        val lastCaller = methodStack.poll()
        val srcMethod = lastCaller.callerMethod

        LogUtil.debug(this, "Resolve from caller method ${srcMethod.name}")
        val srcUnit = lastCaller.callerUnit
        val identifier = (srcUnit as Stmt).invokeExpr.getArg(position).toString()
        val tempCurName = this.curParamName
        this.curParamName = identifier
        backwardSlice(srcMethod, srcUnit)
        this.curParamName = tempCurName
        methodStack.push(CallerMethod(srcUnit, srcMethod))
    }

    /**
     * Resolve the Intent that returned by self-defined function
     * @param sootMethod Self-defined SootMethod
     * @param methodStack Stack contains all methods called
     */
    private fun resolveCalleeReturn(sootMethod: SootMethod) {
        LogUtil.debug(this, "Resolve from self-defined method ${sootMethod.name}")
        if (!sootMethod.isConcrete) {
            return
        }
        val body = sootMethod.retrieveActiveBody()
        body.units.forEach {
            it.apply(
                    object : AbstractStmtSwitch() {
                        override fun caseReturnStmt(stmt: ReturnStmt?) {
                            if (stmt == null) return
                            // the return value must not be null
                            if (stmt.opBox.value.toString() != "null") {
                                val tempCurParamName = this@SuperIntent.curParamName
                                this@SuperIntent.curParamName = stmt.opBox.value.toString()
                                backwardSlice(sootMethod, it)
                                this@SuperIntent.curParamName = tempCurParamName
                            }
                        }
                    }
            )
        }
    }

    /**
     * Use regex expression to match the assigned name in AssignStmt
     * @param name right op in the AssignStmt
     */
    private fun regexMatchName(u: AssignStmt): String {
        val name = u.rightOp.toString()
        val matchResult: String?
        matchResult = when (u.rightOp) {
            is JimpleLocal -> {
                val localRegex = Regex("""\$*r\d+""")
                localRegex.matchEntire(name)!!.value
            }
            else -> name

        }
        return matchResult
    }


    /**
     * Perform backward slice to find the definition point of the Intent as well as called APIs
     * @param sootMethod sootMethod that the unit contained
     * @param unit unit to begin backward slice
     * @param methodStack methodStack from the entry method to current method
     */
    fun backwardSlice(sootMethod: SootMethod, unit: Unit) {
        var u = unit
        var methodBody: Body
        if (sootMethod.hasActiveBody()) {
            methodBody = sootMethod.activeBody
        } else {
            return
        }
        loop@ while (true) {
            try {
                u = methodBody.units.getPredOf(u)
            } catch (e: IllegalStateException) {
                break
            }
            /* Invoke Statement */
            if (u is InvokeStmt) {
                val expr: InvokeExpr = u.invokeExpr
                val name = expr.baseName()
                if (name != this.curParamName) continue@loop
                this.resolveInvokeExpr(u, sootMethod)
            }
            /* Assign Statement */
            if (u is AssignStmt) {
                if (u.leftOp.toString() == this.curParamName) {
                    if (u.containsInvokeExpr()) {
                        val expr: InvokeExpr = u.invokeExpr
                        if (!isSelfDefined(expr.method.declaringClass.name)) {
                            this.resolveAssignExpr(u, sootMethod)
                        } else {
                            methodStack.push(CallerMethod(u, sootMethod))
                            this.resolveCalleeReturn(expr.method)
                            methodStack.poll()
                        }
                    } else {
                        this.curParamName = regexMatchName(u)
                    }
                }
            }
        }
        if (!this.findDef) {
            /* Not find definition of Intent in the method, Intent is passed in, try to trace the caller method */
            val paramLocals = methodBody.parameterLocals.map { it.name }
            if (this.curParamName in paramLocals) {
                resolveCallerPassed(paramLocals.indexOf(this.curParamName))
            }
        }
    }


    abstract fun isSelfDefined(className: String): Boolean
}


class IntentFilter : SuperIntent {
    private val callingAPI = arrayOf("addAction", "addCategory", "addDataType", "addDataScheme", "addDataSchemeSpecificPart", "addDataPath", "addDataAuthority")
    val action: ArrayList<IntentAction> = ArrayList()
    val category: ArrayList<IntentCategory> = ArrayList()
    val data: ArrayList<IntentData> = ArrayList()

    constructor(action: List<IntentAction>, category: List<IntentCategory>, data: List<IntentData>) : super(null, ArrayDeque()) {
        this.action.addAll(action)
        this.category.addAll(category)
        this.data.addAll(data)
        this.findDef = true
    }

    constructor(curParamName: String, methodStack: ArrayDeque<CallerMethod>) : super(curParamName, methodStack) {
        this.findDef = false
    }

    /**
     * Match "actions" between this IntentFilter and Intents
     * @param actions Action list provided by Intent
     * @return If "actions" matched
     */
    private fun matchActions(actions: IntentAction) =
            action.any { it.name == actions.name && it.name != "" } || (actions.name == "" && action.any { it.name != "" })

    /**
     * Match "category" between this IntentFilter and Intents
     * @param categories Category list provided by Intent
     * @return If "category" matched
     */
    private fun matchCategories(intent: Intent): Boolean =
            (category.map { it.name }.containsAll(intent.category.map { it.name }) && intent.category.any { it.name != "" }) || (intent.category.isEmpty() && category.any { it.name != "" })


    /**
     * Match Intent
     * @param intent Target Intent object
     * @return If Intent matched
     */
    fun matchIntent(intent: Intent): Boolean =
            matchActions(intent.action) &&
                    matchCategories(intent) &&
                    matchData(intent)

    private fun matchData(intent: Intent): Boolean {
        return this.data.any { it.match(intent) }
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
        val expr = assignStmt.invokeExpr
        when (expr.method.name) {
            "create" -> {
                resolveInit(expr, assignStmt, sootMethod)
                this.findDef = true
            }
        }
    }

    override fun isSelfDefined(className: String): Boolean = className == "android.content.IntentFilter"

    override fun resolveCallingAPI(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        val args = expr.args
        when (expr.method.name) {
            "addAction" -> {
                this.action.add(IntentAction((args[0].toString())))
            }
            "addCategory" -> {
                this.category.add(IntentCategory((args[0].toString())))
            }
            "addDataType" -> {
                this.data.add(IntentData(mimeType = args[0].toString()))
            }
            "addDataPath" -> {
                this.data.add(IntentData(path = args[0].toString()))
            }
            "addDataAuthority" -> {
                this.data.add(IntentData(host = args[0].toString(), port = args[1].toString()))
            }
            in "addDataScheme" -> {
                this.data.add(IntentData(scheme = args[0].toString()))
            }
        }
    }

    override fun resolveInit(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        val args = expr.args
        when (args.size) {
            1 -> {
                when (args[0].type.toString()) {
                    "android.content.IntentFilter" -> {
                    }
                    "java.lang.String" -> {
                        this.action.add(IntentAction(args[0].toString()))
                    }
                }
            }
            2 -> {
                this.action.add(IntentAction(args[0].toString()))
                this.data.add(IntentData(mimeType = args[1].toString()))
            }
        }
    }
}




/**
 * @property targetComponent Target component for this Intent
 * @property action Actions contained
 * @property type Type info contained
 * @property category Category info contained
 */
class Intent constructor(curParamName: String, methodStack: ArrayDeque<CallerMethod>) : SuperIntent(curParamName, methodStack) {
    private val callingAPI = arrayOf("setComponent", "setClassName", "setClass", "setAction", "addCategory", "setType", "setTypeAndNormalize")
    var targetComponent: String? = null
    var action: IntentAction = IntentAction()
    var category: HashSet<IntentCategory> = HashSet<IntentCategory>()
    var data: IntentData = IntentData()
    var type: IntentType = IntentType()

    /**
     * Parse java.lang.Class argument
     * @param value Object of java.lang.Class
     */
    private fun resolveClassArg(value: Value): String? {
        val clsName = when (value) {
            is ClassConstant -> value.getValue()
            else -> value.toString()
        }
        return clsName.replace('/', '.').replace(";", "")
    }

    override fun resolveInit(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        val argsTypes = expr.method.parameterTypes
        val args = expr.args
        for ((index, argType: Type) in argsTypes.withIndex()) {
            when (argType.toString()) {
                "android.net.Uri" -> {
                    resolveUri(expr, unit, sootMethod, 1)
                }
                "android.content.Intent" -> {
                }
                "java.lang.String" -> {
                    this.action = IntentAction((args[index]).toString())
                }
                "android.content.Context", "android.net.Uri" -> { /* Do nothing */
                }
                "java.lang.Class" -> {
                    val className = resolveClassArg(args[index])
                    this.targetComponent = className
                }
                else -> LogUtil.error(this, "Unmatched when resolve <init>")
            }
        }
    }

    private fun resolveComponentName(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod): Boolean {
        val componentName: ComponentName = ComponentName(expr.getArg(0).toString(), methodStack).also {
            it.backwardSlice(sootMethod, unit)
        }
        if (componentName.findDef) {
            this.targetComponent = componentName.name
            return true
        }
        return false
    }

    private fun resolveUri(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod, pos: Int = 0): Boolean {
        val uri: Uri = Uri(expr.getArg(pos).toString(), methodStack).also {
            it.backwardSlice(sootMethod, unit)
        }
        if (uri.findDef) {
            data.scheme = uri.scheme
            data.path = uri.path
            data.host = uri.host
            data.port = uri.port
            return true
        }
        return false
    }

    private fun resolveUriString(uri: String) {
        val uriData = parse(uri)
        data.port = uriData.port
        data.host = uriData.host
        data.path = uriData.path
        data.scheme = uriData.scheme
    }

    private fun setType(type: String) {
        this.type = IntentType(type)
    }

    override fun resolveCallingAPI(expr: InvokeExpr, unit: Unit, sootMethod: SootMethod) {
        this.curParamName = expr.baseName()
        when (expr.method.name) {
            "setComponent" -> {
                resolveComponentName(expr, unit, sootMethod)
            }
            //setClassName(String packageName, String className) setClassName(Context packageContext, String className)
            "setClassName" -> this.targetComponent = expr.getArg(1).toString()
            //setClass(Context packageContext, Class<?> cls)
            "setClass" -> this.targetComponent = resolveClassArg(expr.getArg(1))
            //setAction(String action)
            "setAction" -> this.action = (IntentAction((expr.getArg(0).toString())))
            //setCategory(String Category)
            "addCategory" -> this.category.add(IntentCategory((expr.getArg(0).toString())))
            in arrayOf("setData", "setDataAndNormalize") -> {
                resolveUri(expr, unit, sootMethod)
            }
            in arrayOf("setDataAndType", "setDataAndTypeAndNormalize") -> {
                resolveUri(expr, unit, sootMethod)
                setType((expr.getArg(1).toString()))
            }
            in arrayOf("setType", "setTypeAndNormalize") -> {
                setType((expr.getArg(0).toString()))
            }
        }
    }

    override fun resolveInvokeExpr(invokeStmt: InvokeStmt, sootMethod: SootMethod) {
        super.resolveInvokeExpr(invokeStmt, sootMethod)
        val expr: InvokeExpr = invokeStmt.invokeExpr
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
            in UNCHANGEAPI -> {
                this.curParamName = expr.baseName()
            }
            "createChooser" -> {
                this.curParamName = (expr.getArg(0) as JimpleLocal).name
            }
            in arrayOf("makeMainActivity", "makeRestartActivityTask") -> {
                this.findDef = resolveComponentName(expr, assignStmt, sootMethod)
            }
            "makeMainSelectorActivity" -> {
                this.action = (IntentAction(expr.getArg(0).toString()))
                this.category.add(IntentCategory(expr.getArg(1).toString()))
                this.findDef = true
            }
            in arrayOf("getIntent", "getIntentOld", "parseUri") -> {
                resolveUriString(expr.getArg(0).toString())
            }
            in callingAPI -> {
                resolveCallingAPI(expr, assignStmt, sootMethod)
            }
        }
    }

    override fun isSelfDefined(className: String): Boolean = className != "android.content.Intent"

    override fun toString(): String = "TargetComponent: ${this.targetComponent}\nAction: ${this.action}\nCategory:${this.category}"
}
