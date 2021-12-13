package me.cirq.aper.entity


class APermission(_name: String) {
    val name: String

    init {
//        println(_name + "      " + Config.get().apkFile)
        require(isPermissionString(_name))
        name = _name.trim()
    }

    override fun hashCode() = name.hashCode()

    override fun equals(other: Any?) = when(other){
        is String -> name == other
        is APermission -> name == other.name
        else -> false
    }

    override fun toString() = name

    companion object {
        val NULL_PERMISSION = APermission("android.permission.NULL")

        fun isPermissionString(str: String): Boolean {
//            return str.matches("""([._0-9a-z]*?)android\.([.a-z]*?)permission\.([_0-9A-Z])+""".toRegex())
            return true     // no universal regex, toooooo difficult
        }
    }
}
