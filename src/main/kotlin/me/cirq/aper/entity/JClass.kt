package me.cirq.aper.entity


class JClass(_name: String) {
    /** For the names:
     * https://stackoverflow.com/questions/15202997
     *
     * (here only accepts full name, i.e., typeName)
     */
    val name: String = _name
    val shortName: String = _name.split(".").last()
    val packageId: String = _name.substringBeforeLast(".", "")

    override fun hashCode() = name.hashCode()

    override fun equals(other: Any?) = when(other){
        is String -> name == other
        is JClass -> name == other.name
        else -> false
    }

    override fun toString() = name
}
