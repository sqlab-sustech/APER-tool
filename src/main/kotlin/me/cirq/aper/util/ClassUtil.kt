package me.cirq.aper.util

import me.cirq.aper.HANDLE_API
import me.cirq.aper.entity.JMethod
import soot.SootClass
import soot.SootMethod


private object Constant {
    val BLACK_LIST: List<String> = listOf(
            "android.", "androidx.", "com.android.", "com.google.android.",
            "java.", "javax.", "kotlin.", "kotlinx.", "io.reactivex.", "rx."
    )

    val SUPPORT_LIST = listOf("android.support.", "androidx.")
}

fun JMethod.isBlackList(): Boolean {
    val clazz = this.definingClass.name
    return Constant.BLACK_LIST.any { clazz.startsWith(it) }
}

fun JMethod.isSupportList(): Boolean {
    val clazz = this.definingClass.name
    return Constant.SUPPORT_LIST.any { clazz.startsWith(it) }
}

fun JMethod.isHandleApi(): Boolean {
    return this.sootSubSignature == HANDLE_API
}

fun SootMethod.isBlackList(): Boolean {
    val clazz = this.declaringClass.name
    return Constant.BLACK_LIST.any { clazz.startsWith(it) }
}

fun SootMethod.isSupportList(): Boolean {
    val clazz = this.declaringClass.name
    return Constant.SUPPORT_LIST.any { clazz.startsWith(it) }
}

fun SootMethod.isHandleApi(): Boolean {
    return this.subSignature == HANDLE_API
}

fun SootClass.isBlackList(): Boolean {
    val clazz = this.name
    return Constant.BLACK_LIST.any { clazz.startsWith(it) }
}
