package me.cirq.aper.entity


sealed class ACallChain(chain: List<JMethod>): Iterable<JMethod> {
    val chain: List<JMethod> = ArrayList(chain)
    val chainSize: Int get() = chain.size
    val api = this.chain.last()

    operator fun get(index: Int) = chain[index]

    override fun iterator() = chain.iterator()
}


/* Stands for Dangerous Call Chain */
class DCallChain(chain: List<JMethod>, permissions: Set<APermission>): ACallChain(chain) {
    val permissions = HashSet(permissions)
}


/* Stands for Permission Maintaining Call Chain */
class PCallChain(chain: List<JMethod>, permissions: Set<APermission>): ACallChain(chain) {
    val permissions = HashSet(permissions)
}


///* Stands for CHECK Call Chain */
//class CCallChain(chain: List<JMethod>, _permission: APermission): ACallChain(chain) {
//    val permission = _permission
//}
//
///* Stands for REQUEST Call Chain */
//class RCallChain(chain: List<JMethod>, permissions: List<APermission>): ACallChain(chain) {
//    val permissions = ArrayList(permissions)
//}
