package me.cirq.aper.mapping

import me.cirq.aper.entity.JMethod


enum class PermissionCombination {
    AnyOf, AllOf;

    companion object {
        private val combinationType: MutableMap<JMethod,PermissionCombination> = HashMap()

        fun put(method: JMethod, type: String){
            combinationType[method] = when(type.toLowerCase()) {
                "anyof" -> AnyOf
                "allof" -> AllOf
                else -> throw IllegalArgumentException("unknown combination type $type")
            }
        }

        fun get(method: JMethod): PermissionCombination {
            return combinationType[method]?: AnyOf  // fallback since any is majority
        }
    }
}
