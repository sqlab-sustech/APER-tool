package me.cirq.aper.util

import me.cirq.aper.entity.JMethod
import soot.*
import soot.jimple.CaughtExceptionRef
import soot.jimple.InstanceInvokeExpr
import soot.jimple.InvokeExpr
import soot.jimple.JasminClass
import soot.options.Options
import soot.toolkits.graph.Block
import soot.util.Chain
import soot.util.JasminOutputStream
import java.io.FileOutputStream
import java.io.OutputStreamWriter
import java.io.PrintWriter


fun Scene.init() {
    soot.G.reset()
    Options.v().apply {
        set_allow_phantom_refs(true)
        set_whole_program(true)
        set_prepend_classpath(true)
        set_process_multiple_dex(true)
        set_validate(true)
    }
}

fun Scene.apply_options(block: Options.() -> Unit) {
    Options.v().apply(block)
}

fun Scene.getMethod(jMethod: JMethod): SootMethod {
    return this.getMethod(jMethod.sootSignature)
}

fun Block.isCatch(): Boolean {
    val head = this.first()
    return (head is IdentityUnit) && (head.rightOp is CaughtExceptionRef)
}

fun InvokeExpr.baseName(): String = when (this) {
    is InstanceInvokeExpr -> this.base.toString()
    else -> ""
}

fun SootClass.dumpToClassFile() {
    val fn = SourceLocator.v().getFileNameFor(this, Options.output_format_class)
    JasminOutputStream(FileOutputStream(fn)).use{
        PrintWriter(OutputStreamWriter(it)).use{ outWriter ->
            JasminClass(this).print(outWriter)
            outWriter.flush()
        }
    }
}

fun soot.Unit.getUseAndDef(): List<Value> {
    return this.useAndDefBoxes.map{ it.value }
}

fun Value.isStringType(): Boolean {
    return this.type.toString().startsWith("java.lang.String")
}

fun Value.isIntType(): Boolean {
    return this.type.toString() == "int"
}

fun <E> Chain<E>.safeGetPredOf(point: E): E? =
        try { this.getPredOf(point) }
        catch (_: NoSuchElementException) { null }

fun <E> Chain<E>.safeGetSuccOf(point: E): E? =
        try { this.getSuccOf(point) }
        catch (_: NoSuchElementException) { null }

fun Pack.addTransform(phaseName: String, t: Transformer) {
    add(Transform(phaseName, t))
}
