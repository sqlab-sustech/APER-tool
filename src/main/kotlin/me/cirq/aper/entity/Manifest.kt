package me.cirq.aper.entity

import org.dom4j.*
import java.util.*


data class ManiFestData(
        val activity: List<Activity>,
        val activityAlias: List<ActivityAlias>,
        val service: List<Service>,
        val receiver: List<Receiver>,
        val provider: List<Provider>
)


class Manifest(manifest: ManiFestData) {
    val receiver: ArrayList<Receiver> = ArrayList()
    val service: ArrayList<Service> = ArrayList()
    val activity: ArrayList<Activity> = ArrayList()

    init {
        receiver.addAll(manifest.receiver)
        service.addAll(manifest.service)
        activity.addAll(manifest.activity)
    }

    fun getNames(): HashSet<String> {
        return (activity.map { it.name } +
                service.map { it.name } +
                receiver.map { it.name }).toHashSet()
    }

    fun addReceiver(receiver: Receiver) {
        this.receiver.add(receiver)
    }
}


class ManifestParser private constructor(private val document: Document) {
    constructor(text: String) : this(DocumentHelper.parseText(text))

    private val root = document.rootElement
    private val application = root.element("application")

    private val `package` = root.attributeValue("package")

    companion object {
        private val NAMESPACE = Namespace("android", "http://schemas.android.com/apk/res/android")
    }


    fun parse(): Manifest {
        val activity = parseActivity()
        val activityAlias = parseActivityAlias()
        val service = parseService()
        val receiver = parseReceiver()
        val provider = parseProvider()
        return Manifest(ManiFestData(activity, activityAlias, service, receiver, provider))
    }

    private fun parseActivity(): List<Activity> {
        return application.elems("activity").map { activity ->

            val name = getComponentName(activity)
            val intentFilter = parseIntentFilter(activity)

            Activity(name, intentFilter)
        }
    }

    private fun parseActivityAlias(): List<ActivityAlias> {
        return application.elems("activity-alias").map { alias ->

            val name = getComponentName(alias)
            val targetActivity = getComponentName(alias, attribute = "targetActivity")
            val intentFilter = parseIntentFilter(alias)

            ActivityAlias(name, targetActivity, intentFilter)
        }
    }

    private fun parseService(): List<Service> {
        return application.elems("service").map { service ->

            val name = getComponentName(service)
            val intentFilter = parseIntentFilter(service)

            Service(name, intentFilter)
        }
    }

    private fun parseReceiver(): List<Receiver> {
        return application.elems("receiver").map { receiver ->

            val name = getComponentName(receiver)
            val intentFilter = parseIntentFilter(receiver)

            Receiver(name, intentFilter)
        }
    }

    private fun parseProvider(): List<Provider> {
        return application.elems("provider").map { provider ->

            val name = getComponentName(provider)

            Provider(name)
        }
    }

    private fun getComponentName(element: Element, attribute: String = "name"): String {
        return element.attributeValue(attribute).let {
            if (it.startsWith(".")) "$`package`$it" else it
        }
    }

    private fun parseIntentFilter(element: Element): List<IntentFilter> {
        return element.elems("intent-filter").map { filter ->

            val action = filter.elems("action").map { action ->
                IntentAction(action.attrNamespace("name"))
            }
            val category = filter.elems("category").map { category ->
                IntentCategory(category.attrNamespace("name"))
            }
            val data = filter.elems("data").map { data ->
                IntentData(
                        data.attrNamespace("scheme") ?: "",
                        data.attrNamespace("host") ?: "",
                        data.attrNamespace("port") ?: "",
                        data.attrNamespace("path") ?: "",
                        data.attrNamespace("pathPattern") ?: "",
                        data.attrNamespace("pathPrefix") ?: "",
                        data.attrNamespace("mimeType") ?: ""
                )
            }

            IntentFilter(action, category, data)
        }
    }

    private fun Element.elem(name: String) = this.element(name)

    private fun Element.elems(name: String) = this.elements(name).map { it as Element }

    private fun Element.attr(name: String) = this.attributeValue(name)

    private fun Element.attrNamespace(name: String, namespace: Namespace = NAMESPACE) =
            this.attributeValue(QName.get(name, namespace))
}
