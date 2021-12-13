package me.cirq.aper.entity

import soot.SootMethod
import java.util.regex.Pattern


class JMethod(val methodName: String,
              val definingClass: JClass,
              val retClass: JClass,
              val paramClasses: List<JClass>) {

    val name: String by lazy {
        val paramStrings = paramClasses.map{ it.toString() }
        val params = paramStrings.joinToString(",")
        "$definingClass.$methodName($params)$retClass"
    }

    val sootSignature: String by lazy {
        val paramStrings = paramClasses.map{ it.toString() }
        val params = paramStrings.joinToString(",")
        "<$definingClass: $retClass $methodName($params)>"
    }

    val sootSubSignature: String by lazy {
        val paramStrings = paramClasses.map{ it.toString() }
        val params = paramStrings.joinToString(",")
        "$retClass $methodName($params)"
    }

    override fun hashCode() = name.hashCode()

    override fun equals(other: Any?) = when(other){
        is String -> name == other
        is JMethod -> name == other.name
        else -> false
    }

    override fun toString() = name

    companion object {
        private val SOOT_METHOD_PATTERN = Pattern.compile("^<(.+?): (.+?) (.+?)\\((.*?)\\)>$")
        fun fromSootSignature(sig: String): JMethod {
            val m = SOOT_METHOD_PATTERN.matcher(sig)
            return if (m.find()) {
                val method = m.group(3)
                val definingClass = JClass(m.group(1))
                val retClass = JClass(m.group(2))
                val paramClasses = m.group(4).split(",").map{ JClass(it) }
                JMethod(method, definingClass, retClass, paramClasses)
            } else {
                throw IllegalArgumentException("not a valid method: $sig")
            }
        }

        private val AXP_METHOD_PATTERN = Pattern.compile("^(.*?)\\.(\\w+)\\((.*?)\\)(.*?)$")
        fun fromAxplorerSignature(sig: String): JMethod {
            val m = AXP_METHOD_PATTERN.matcher(sig)
            return if (m.find()) {
                val method = m.group(2)
                val definingClass = JClass(m.group(1))
                val retClass = JClass(m.group(4))
                val paramClasses = m.group(3).split(",").map{ JClass(it) }
                JMethod(method, definingClass, retClass, paramClasses)
            } else {
                throw IllegalArgumentException("not a valid method: $sig")
            }
        }

        fun fromSootMethod(method: SootMethod): JMethod {
            return fromSootSignature(method.signature)
        }
    }
}
