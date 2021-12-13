package me.cirq.aper.transformer

import soot.*
import java.util.*


class ObfuscationDetectTransformer: SceneTransformer() {

    companion object {
        val membersMap: MutableMap<String, MutableList<String>> = HashMap()
    }

    override fun internalTransform(phaseName: String, options: Map<String, String>) {
        Scene.v().applicationClasses.forEach { cls ->
            val mbs: MutableList<String> = LinkedList()
            cls.name.takeIf { "\$" !in it }?.let{ mbs.add(it) }
            cls.fields.forEach { mbs.add(it.name) }
            cls.methods.filter { it.name !in setOf("<init>", "<clinit>") }
                       .forEach { mbs.add(it.name) }
            val clsname = cls.name
            if (membersMap.containsKey(clsname))
                membersMap[clsname]!! += mbs
            else
                membersMap[clsname] = mbs
        }
    }

}
